#include <iostream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <thread>
#include <mutex>
#include "crypto_utils.h"

using namespace std;

string current_partner = "";
mutex partner_mutex;
string aes_key = "";

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
                    cout << "\n[" << sender << "]: " << content << "\n> " << flush;
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

    // Phase 2: DH Key Exchange
    DHKeyExchange dh;
    string my_pub = dh.get_public_key_hex();
    string init_msg = "DH_INIT " + my_pub + "\n";
    send(sock, init_msg.c_str(), init_msg.length(), 0);

    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
    string reply(buffer);
    
    if (reply.rfind("DH_ACK ", 0) != 0) {
        cout << "Failed DH Handshake.\n";
        return 1;
    }
    
    size_t newline = reply.find("\n");
    string server_pub = reply.substr(7, newline - 7);
    
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
                send_packet(sock, "@" + partner + " " + msg);
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
                send_packet(sock, "@" + p + " " + input);
            }
        }
    }

    close(sock);
    return 0;
}
