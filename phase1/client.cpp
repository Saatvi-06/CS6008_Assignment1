#include <iostream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <thread>
#include <mutex>

using namespace std;

string current_partner = "";
mutex partner_mutex;

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
            string line = data.substr(0, pos);
            data.erase(0, pos + 1);
            
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
    string packet = msg + "\n";
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
    if (sock == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("connect");
        return 1;
    }

    cout << "Enter your username: ";
    string username;
    getline(cin, username);

    send_packet(sock, "LOGIN " + username);

    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes <= 0) {
        cout << "Failed to login.\n";
        return 1;
    }
    string reply(buffer);
    if (reply.find("LOGIN_OK") != 0) {
        cout << "Login failed: " << reply << "\n";
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

