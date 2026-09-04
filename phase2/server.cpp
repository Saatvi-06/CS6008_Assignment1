#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <algorithm>
#include "crypto_utils.h"

using namespace std;

#define MAX_CLIENTS 2

map<string, int> clients;
map<int, string> client_names;
map<int, string> client_keys; // Stores AES-GCM key for each socket

void send_encrypted(int sock, const string& msg) {
    if (client_keys.count(sock)) {
        string enc = encrypt_aes_gcm(msg, client_keys[sock]);
        string packet = enc + "\n";
        send(sock, packet.c_str(), packet.length(), 0);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <port>\n";
        return 1;
    }

    int port = stoi(argv[1]);
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_fd, 5);

    cout << "Phase 2 Server listening on port " << port << "...\n";

    fd_set master_set, read_set;
    FD_ZERO(&master_set);
    FD_SET(server_fd, &master_set);
    int max_fd = server_fd;

    while (true) {
        read_set = master_set;
        if (select(max_fd + 1, &read_set, NULL, NULL, NULL) == -1) break;

        for (int i = 0; i <= max_fd; i++) {
            if (FD_ISSET(i, &read_set)) {
                if (i == server_fd) {
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);
                    int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
                    if (client_fd != -1) {
                        FD_SET(client_fd, &master_set);
                        if (client_fd > max_fd) max_fd = client_fd;
                        cout << "New connection on socket " << client_fd << "\n";
                    }
                } else {
                    char buffer[8192];
                    memset(buffer, 0, sizeof(buffer));
                    int bytes_received = recv(i, buffer, sizeof(buffer) - 1, 0);
                    
                    if (bytes_received <= 0) {
                        cout << "Socket " << i << " disconnected.\n";
                        close(i);
                        FD_CLR(i, &master_set);
                        client_keys.erase(i);
                        if (client_names.count(i)) {
                            string name = client_names[i];
                            clients.erase(name);
                            client_names.erase(i);
                            cout << "User " << name << " logged out.\n";
                        }
                    } else {
                        string msg(buffer);
                        size_t pos = 0;
                        while ((pos = msg.find("\n")) != string::npos) {
                            string line = msg.substr(0, pos);
                            msg.erase(0, pos + 1);
                            if (line.empty()) continue;

                            // Handle DH Handshake first if not established
                            if (!client_keys.count(i)) {
                                if (line.rfind("DH_INIT ", 0) == 0) {
                                    string client_pub = line.substr(8);
                                    DHKeyExchange dh;
                                    string my_pub = dh.get_public_key_hex();
                                    string aes_key = dh.compute_shared_secret(client_pub);
                                    client_keys[i] = aes_key;
                                    
                                    cout << "[Socket " << i << "] Shared Secret Fingerprint: " << aes_key << "\n";
                                    
                                    string reply = "DH_ACK " + my_pub + "\n";
                                    send(i, reply.c_str(), reply.length(), 0);
                                }
                                continue;
                            }

                            // If DH is done, all incoming lines are AES-GCM ciphertexts
                            string dec = decrypt_aes_gcm(line, client_keys[i]);
                            if (dec.empty()) {
                                cout << "[Security Warning] Failed to decrypt packet from socket " << i << "\n";
                                continue;
                            }

                            if (!client_names.count(i)) {
                                if (dec.rfind("LOGIN ", 0) == 0) {
                                    string username = dec.substr(6);
                                    if (clients.count(username)) {
                                        send_encrypted(i, "LOGIN_ERR");
                                    } else if (clients.size() >= MAX_CLIENTS) {
                                        send_encrypted(i, "ERROR Server full");
                                    } else {
                                        clients[username] = i;
                                        client_names[i] = username;
                                        send_encrypted(i, "LOGIN_OK");
                                        cout << "User " << username << " logged in.\n";
                                    }
                                } else {
                                    send_encrypted(i, "ERROR Please LOGIN first");
                                }
                            } else {
                                string sender = client_names[i];
                                if (dec == "/who") {
                                    string who_list = "WHO ";
                                    for (auto const& [name, sock] : clients) {
                                        who_list += name + ",";
                                    }
                                    if (who_list.back() == ',') who_list.pop_back();
                                    send_encrypted(i, who_list);
                                } else if (dec.rfind("@", 0) == 0) {
                                    size_t space_pos = dec.find(" ");
                                    if (space_pos != string::npos) {
                                        string recipient = dec.substr(1, space_pos - 1);
                                        string content = dec.substr(space_pos + 1);
                                        cout << "[SERVER LOG] " << sender << " -> " << recipient << ": " << content << "\n";
                                        if (clients.count(recipient)) {
                                            if (content.rfind("/tamper ", 0) == 0) {
                                                string tampered_msg = content.substr(8);
                                                string enc = encrypt_aes_gcm("@" + sender + " " + tampered_msg, client_keys[clients[recipient]]);
                                                enc[enc.length() - 1] ^= 0x01; // Corrupt the ciphertext
                                                string packet = enc + "\n";
                                                send(clients[recipient], packet.c_str(), packet.length(), 0);
                                                cout << "[SERVER LOG] Forwarded intentionally TAMPERED ciphertext to " << recipient << "!\n";
                                            } else {
                                                send_encrypted(clients[recipient], "@" + sender + " " + content);
                                            }
                                        } else {
                                            send_encrypted(i, "ERROR User " + recipient + " not online.");
                                        }
                                    }
                                } else {
                                    send_encrypted(i, "ERROR Invalid command.");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    close(server_fd);
    return 0;
}
