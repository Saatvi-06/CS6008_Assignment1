#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <algorithm>

using namespace std;

#define MAX_CLIENTS 2

map<string, int> clients;
map<int, string> client_names;

void send_to_client(int sock, const string& msg) {
    string packet = msg + "\n";
    send(sock, packet.c_str(), packet.length(), 0);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <port>\n";
        return 1;
    }

    int port = stoi(argv[1]);
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        return 1;
    }

    if (listen(server_fd, 5) == -1) {
        perror("listen");
        return 1;
    }

    cout << "Server listening on port " << port << "...\n";

    fd_set master_set, read_set;
    FD_ZERO(&master_set);
    FD_SET(server_fd, &master_set);
    int max_fd = server_fd;

    while (true) {
        read_set = master_set;
        if (select(max_fd + 1, &read_set, NULL, NULL, NULL) == -1) {
            perror("select");
            break;
        }

        for (int i = 0; i <= max_fd; i++) {
            if (FD_ISSET(i, &read_set)) {
                if (i == server_fd) {
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);
                    int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
                    if (client_fd == -1) {
                        perror("accept");
                    } else {
                        FD_SET(client_fd, &master_set);
                        if (client_fd > max_fd) max_fd = client_fd;
                        cout << "New connection on socket " << client_fd << "\n";
                    }
                } else {
                    char buffer[4096];
                    memset(buffer, 0, sizeof(buffer));
                    int bytes_received = recv(i, buffer, sizeof(buffer) - 1, 0);
                    
                    if (bytes_received <= 0) {
                        if (bytes_received == 0) {
                            cout << "Socket " << i << " disconnected.\n";
                        } else {
                            perror("recv");
                        }
                        close(i);
                        FD_CLR(i, &master_set);
                        if (client_names.count(i)) {
                            string name = client_names[i];
                            clients.erase(name);
                            client_names.erase(i);
                            cout << "User " << name << " logged out.\n";
                        }
                    } else {
                        string msg(buffer);
                        // Process multiple messages separated by newline
                        size_t pos = 0;
                        while ((pos = msg.find("\n")) != string::npos) {
                            string line = msg.substr(0, pos);
                            msg.erase(0, pos + 1);
                            
                            if (line.empty()) continue;
                            
                            if (!client_names.count(i)) {
                                if (line.rfind("LOGIN ", 0) == 0) {
                                    string username = line.substr(6);
                                    if (clients.count(username)) {
                                        send_to_client(i, "LOGIN_ERR");
                                    } else if (clients.size() >= MAX_CLIENTS) {
                                        send_to_client(i, "ERROR Server full");
                                    } else {
                                        clients[username] = i;
                                        client_names[i] = username;
                                        send_to_client(i, "LOGIN_OK");
                                        cout << "User " << username << " logged in.\n";
                                    }
                                } else {
                                    send_to_client(i, "ERROR Please LOGIN first");
                                }
                            } else {
                                string sender = client_names[i];
                                if (line == "/who") {
                                    string who_list = "WHO ";
                                    for (auto const& [name, sock] : clients) {
                                        who_list += name + ",";
                                    }
                                    if (who_list.back() == ',') who_list.pop_back();
                                    send_to_client(i, who_list);
                                } else if (line.rfind("@", 0) == 0) {
                                    size_t space_pos = line.find(" ");
                                    if (space_pos != string::npos) {
                                        string recipient = line.substr(1, space_pos - 1);
                                        string content = line.substr(space_pos + 1);
                                        cout << "[SERVER LOG] " << sender << " -> " << recipient << ": " << content << "\n";
                                        if (clients.count(recipient)) {
                                            send_to_client(clients[recipient], "@" + sender + " " + content);
                                        } else {
                                            send_to_client(i, "ERROR User " + recipient + " not online.");
                                        }
                                    }
                                } else {
                                    send_to_client(i, "ERROR Invalid command.");
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

