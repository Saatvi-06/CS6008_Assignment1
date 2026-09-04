#include <iostream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <thread>
#include <mutex>
#include <map>
#include "crypto_utils.h"

using namespace std;

string current_partner = "";
mutex partner_mutex;
string aes_key = "";

map<string, string> e2e_keys;
map<string, DHKeyExchange*> pending_dh;
mutex e2e_mutex;

void send_packet(int sock, const string& msg);

void receive_messages(int sock) {
    char buffer[4096];
    string leftover = "";
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0) {
            cout << "\nDisconnected from server.\n";
            exit(0);
        }
        
        string data = leftover + string(buffer);
        size_t pos = 0;
        while ((pos = data.find("\n")) != string::npos) {
            string enc_line = data.substr(0, pos);
            data.erase(0, pos + 1);
            if (enc_line.empty()) continue;

            string line = decrypt_aes_gcm(enc_line, aes_key);
            if (line.empty()) {
                cout << "\n[Security Error] Dropping tampered or invalid ciphertext!\n> " << flush;
                continue;
            }
            
            if (line.rfind("WHO ", 0) == 0) {
                cout << "\n[Online users]: " << line.substr(4) << "\n> " << flush;
            } else if (line.rfind("@", 0) == 0) {
                size_t space_pos = line.find(" ");
                if (space_pos != string::npos) {
                    string sender = line.substr(1, space_pos - 1);
                    string content = line.substr(space_pos + 1);
                    
                    if (content.rfind("__E2E_INIT__", 0) == 0) {
                        string pub = content.substr(12);
                        e2e_mutex.lock();
                        DHKeyExchange* dh = new DHKeyExchange();
                        string my_pub = dh->get_public_key_hex();
                        string key = dh->compute_shared_secret(pub);
                        e2e_keys[sender] = key;
                        e2e_mutex.unlock();
                        
                        cout << "\n[PKI/E2E] Established E2E Session with " << sender << "\n";
                        cout << "[E2E Handshake] Key Fingerprint: " << key << "\n> " << flush;
                        
                        send_packet(sock, "@" + sender + " __E2E_ACK__" + my_pub);
                        delete dh;
                    } else if (content.rfind("__E2E_ACK__", 0) == 0) {
                        string pub = content.substr(11);
                        e2e_mutex.lock();
                        if (pending_dh.find(sender) != pending_dh.end()) {
                            DHKeyExchange* dh = pending_dh[sender];
                            string key = dh->compute_shared_secret(pub);
                            e2e_keys[sender] = key;
                            delete dh;
                            pending_dh.erase(sender);
                            
                            cout << "\n[PKI/E2E] Established E2E Session with " << sender << "\n";
                            cout << "[E2E Handshake] Key Fingerprint: " << key << "\n> " << flush;
                        }
                        e2e_mutex.unlock();
                    } else if (content.rfind("__E2E_MSG__", 0) == 0) {
                        string enc_inner = content.substr(11);
                        e2e_mutex.lock();
                        string key = e2e_keys.count(sender) ? e2e_keys[sender] : "";
                        e2e_mutex.unlock();
                        
                        if (key.empty()) {
                            cout << "\n[" << sender << "]: [Encrypted E2E Message but no key established!]\n> " << flush;
                        } else {
                            string dec_inner = decrypt_aes_gcm(enc_inner, key);
                            if (dec_inner.empty()) {
                                cout << "\n[Security Error] Failed to decrypt E2E message from " << sender << "!\n> " << flush;
                            } else {
                                cout << "\n[" << sender << " (E2E)]: " << dec_inner << "\n> " << flush;
                            }
                        }
                    } else {
                        cout << "\n[" << sender << "]: " << content << "\n> " << flush;
                    }
                }
            } else if (line.rfind("ERROR ", 0) == 0) {
                cout << "\n[Error]: " << line.substr(6) << "\n> " << flush;
            }
        }
        leftover = data;
    }
}

void send_packet(int sock, const string& msg) {
    string enc_msg = encrypt_aes_gcm(msg, aes_key);
    string packet = enc_msg + "\n";
    send(sock, packet.c_str(), packet.length(), 0);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <server_ip> <port>\n";
        return 1;
    }

    string server_ip = argv[1];
    int port = stoi(argv[2]);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("connect");
        return 1;
    }

    // Phase 3: Receive and Validate Server Certificate
    char buffer[8192];
    string cert_data = "";
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            cout << "Connection closed during cert exchange.\n";
            return 1;
        }
        cert_data += string(buffer);
        if (cert_data.find("EOF_CERT\n") != string::npos) {
            break;
        }
    }
    
    // Extract actual cert string
    size_t start = cert_data.find("CERT\n") + 5;
    size_t end = cert_data.find("EOF_CERT\n");
    string server_cert = cert_data.substr(start, end - start);
    
    X509* cert = validate_certificate(server_cert, "certs/ca.crt", server_ip);
    if (!cert) {
        cout << "[Security Alert] Certificate validation failed! Aborting connection.\n";
        close(sock);
        return 1;
    }
    cout << "[PKI] Server Certificate Validated successfully (Signed by trusted CA).\n";

    // Extract Public Key from Certificate
    EVP_PKEY* server_pubkey = X509_get_pubkey(cert);
    X509_free(cert);

    // Phase 2/3: DH Key Exchange
    DHKeyExchange dh;
    string my_pub = dh.get_public_key_hex();
    string init_msg = "DH_INIT " + my_pub + "\n";
    send(sock, init_msg.c_str(), init_msg.length(), 0);

    memset(buffer, 0, sizeof(buffer));
    int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
    string reply(buffer);
    
    if (reply.rfind("DH_ACK ", 0) != 0) {
        cout << "Failed DH Handshake.\n";
        return 1;
    }
    
    size_t space1 = reply.find(" ");
    size_t space2 = reply.find(" ", space1 + 1);
    size_t newline = reply.find("\n");
    
    string server_pub = reply.substr(space1 + 1, space2 - space1 - 1);
    string sig_hex = reply.substr(space2 + 1, newline - space2 - 1);
    
    // Convert hex signature back to binary
    string signature = "";
    for (size_t i = 0; i < sig_hex.length(); i += 2) {
        string byteString = sig_hex.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), NULL, 16);
        signature += byte;
    }
    
    // Verify Proof-of-Possession Signature
    if (!verify_signature(server_pub, signature, server_pubkey)) {
        cout << "[Security Alert] Proof-of-Possession signature verification failed! Server does not possess private key. Aborting!\n";
        EVP_PKEY_free(server_pubkey);
        close(sock);
        return 1;
    }
    cout << "[PKI] Server Proof-of-Possession Verified successfully (Signature matched).\n";
    EVP_PKEY_free(server_pubkey);
    
    aes_key = dh.compute_shared_secret(server_pub);
    cout << "[DH Handshake Complete] AES Key Fingerprint: " << aes_key << "\n";

    cout << "Enter your username: ";
    string username;
    getline(cin, username);
    username.erase(username.find_last_not_of(" \n\r\t") + 1);

    send_packet(sock, "LOGIN " + username);

    memset(buffer, 0, sizeof(buffer));
    bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
    
    string enc_reply = string(buffer);
    enc_reply = enc_reply.substr(0, enc_reply.find("\n"));
    string dec_reply = decrypt_aes_gcm(enc_reply, aes_key);

    if (dec_reply.find("LOGIN_OK") != 0) {
        cout << "Login failed: " << dec_reply << "\n";
        return 1;
    }

    cout << "Logged in successfully.\n";

    thread recv_thread(receive_messages, sock);
    recv_thread.detach();

    string input;
    while (true) {
        cout << "> " << flush;
        if (!getline(cin, input)) break;
        if (input.empty()) continue;

        if (input.rfind("@", 0) == 0) {
            size_t space_pos = input.find(" ");
            if (space_pos != string::npos) {
                string partner = input.substr(1, space_pos - 1);
                string msg = input.substr(space_pos + 1);
                partner_mutex.lock();
                current_partner = partner;
                partner_mutex.unlock();
                
                e2e_mutex.lock();
                string key = e2e_keys.count(partner) ? e2e_keys[partner] : "";
                e2e_mutex.unlock();
                
                if (!key.empty()) {
                    string inner_enc = encrypt_aes_gcm(msg, key);
                    send_packet(sock, "@" + partner + " __E2E_MSG__" + inner_enc);
                } else {
                    send_packet(sock, "@" + partner + " " + msg);
                }
            } else {
                cout << "Invalid format. Use: @username message\n";
            }
        } else if (input.rfind("/tamper ", 0) == 0) {
            size_t space_pos = input.find(" ", 8);
            if (space_pos != string::npos) {
                string partner = input.substr(8, space_pos - 8);
                string msg = input.substr(space_pos + 1);
                
                string plaintext = "@" + partner + " " + msg;
                string enc_msg = encrypt_aes_gcm(plaintext, aes_key);
                
                // FLIP ONE BIT IN THE CIPHERTEXT TO DEMONSTRATE TAMPERING
                enc_msg[enc_msg.length() - 1] ^= 0x01; 
                
                string packet = enc_msg + "\n";
                send(sock, packet.c_str(), packet.length(), 0);
                cout << "[TAMPER] Sent intentionally corrupted AES-GCM ciphertext to the server!\n";
            } else {
                cout << "Invalid format. Use: /tamper @username message\n";
            }
        } else if (input.rfind("/e2e ", 0) == 0) {
            string partner = input.substr(5);
            e2e_mutex.lock();
            DHKeyExchange* dh = new DHKeyExchange();
            pending_dh[partner] = dh;
            string pub = dh->get_public_key_hex();
            e2e_mutex.unlock();
            
            cout << "[E2E] Initiating handshake with " << partner << "...\n";
            send_packet(sock, "@" + partner + " __E2E_INIT__" + pub);
        } else if (input.rfind("/chat ", 0) == 0) {
            partner_mutex.lock();
            current_partner = input.substr(6);
            partner_mutex.unlock();
            cout << "Chat partner set to " << current_partner << "\n";
        } else if (input == "/who") {
            send_packet(sock, "/who");
        } else if (input == "/quit") {
            break;
        } else {
            partner_mutex.lock();
            string p = current_partner;
            partner_mutex.unlock();
            if (p.empty()) {
                cout << "No chat partner selected. Use /chat <username> or @username <message>\n";
            } else {
                e2e_mutex.lock();
                string key = e2e_keys.count(p) ? e2e_keys[p] : "";
                e2e_mutex.unlock();
                
                if (!key.empty()) {
                    string inner_enc = encrypt_aes_gcm(input, key);
                    send_packet(sock, "@" + p + " __E2E_MSG__" + inner_enc);
                } else {
                    send_packet(sock, "@" + p + " " + input);
                }
            }
        }
    }

    close(sock);
    return 0;
}
