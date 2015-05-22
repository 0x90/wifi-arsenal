/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * Author: Matias Fontanini <matias.fontanini@gmail.com>
 * 
 * This small application decrypts WEP/WPA2(AES and TKIP) traffic on
 * the fly and writes the result into a tap interface. 
 * 
 */

// libtins
#include <tins/tins.h>
// linux/POSIX stuff
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
// STL
#include <iostream>
#include <atomic>
#include <algorithm>
#include <tuple>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <memory>

using namespace Tins;

// our running flag
std::atomic<bool> running;

// unique_fd - just a wrapper over a file descriptor which closes
// the fd in its dtor. non-copyable but movable

class unique_fd {
public:
    static constexpr int invalid_fd = -1;

    unique_fd(int fd = invalid_fd) 
    : fd(fd) 
    {
        
    }
    
    
    unique_fd(unique_fd &&rhs) 
    : fd(invalid_fd)
    {
        *this = std::move(rhs);
    }
    
    unique_fd& operator=(unique_fd&& rhs) 
    {
        if(fd != invalid_fd)
            ::close(fd);
        fd = invalid_fd;
        std::swap(fd, rhs.fd);
        return *this;
    }
    
    ~unique_fd() 
    {
        if(fd != invalid_fd)
            ::close(fd);
    }
    
    unique_fd(const unique_fd&) = delete;
    unique_fd& operator=(const unique_fd&) = delete;
    
    int operator*() 
    {
        return fd;
    }
    
    operator bool() const
    {
        return fd != invalid_fd;
    }
private:
    int fd;
};

// packet_buffer - buffers packets, decrypts them and flushes them into 
// the interface using an auxiliary thread.

class packet_buffer {
public:
    typedef std::unique_ptr<PDU> unique_pdu;

    packet_buffer(unique_fd fd, Crypto::WPA2Decrypter wpa2d,
      Crypto::WEPDecrypter wepd)
    : fd(std::move(fd)), wpa2_decrypter(std::move(wpa2d)), 
    wep_decrypter(std::move(wepd))
    {
        
    }
    
    packet_buffer(const packet_buffer&) = delete;
    packet_buffer& operator=(const packet_buffer&) = delete;
    
    ~packet_buffer() {
        thread.join();
    }
    
    void add_packet(unique_pdu pkt) 
    {
        std::lock_guard<std::mutex> _(mtx);
        packet_queue.push(std::move(pkt));
        cond.notify_one();
    }
    
    void stop_running() 
    {
        std::lock_guard<std::mutex> _(mtx);
        cond.notify_one();
    }
    
    void run() 
    {
        thread = std::thread(&packet_buffer::thread_proc, this);
    }    
private:
    EthernetII make_eth_packet(Dot11Data &dot11)
    {
        if(dot11.from_ds() && !dot11.to_ds())
            return EthernetII(dot11.addr1(), dot11.addr3());
        else if(!dot11.from_ds() && dot11.to_ds())
            return EthernetII(dot11.addr3(), dot11.addr2());
        else 
            return EthernetII(dot11.addr1(), dot11.addr2());
    }
    
    template<typename Decrypter>
    bool try_decrypt(Decrypter &decrypter, PDU &pdu) 
    {
        if(decrypter.decrypt(pdu)) {
            auto &dot11 = pdu.rfind_pdu<Dot11Data>();
            auto &snap = pdu.rfind_pdu<SNAP>();
            // create an EthernetII using the src and dst addrs
            auto pkt = make_eth_packet(dot11);
            // move the inner pdu into the EthernetII to avoid copying
            pkt.inner_pdu(snap.release_inner_pdu());
            auto buffer = pkt.serialize();
            if(write(*fd, buffer.data(), buffer.size()) == -1)
                throw std::runtime_error("Error writing to tap interface");
            // if the decrypter is successfull, then SUCCESS
            return true;
        }
        return false;
    }

    void thread_proc() 
    {
        while(running) {
            unique_pdu pkt;
            // critical section
            {
                std::unique_lock<std::mutex> lock(mtx);
                if(!running)
                    return;
                if(packet_queue.empty()) {
                    cond.wait(lock);
                    // if it's still empty, then we're done
                    if(packet_queue.empty())
                        return;
                }
                pkt = std::move(packet_queue.front());
                packet_queue.pop();
            }
            // non-critical section
            if(!try_decrypt(wpa2_decrypter, *pkt.get())) 
                try_decrypt(wep_decrypter, *pkt.get());
        }
    }

    unique_fd fd;
    std::thread thread;
    std::mutex mtx;
    std::condition_variable cond;
    std::queue<unique_pdu> packet_queue;
    Crypto::WPA2Decrypter wpa2_decrypter;
    Crypto::WEPDecrypter wep_decrypter;
};


// traffic_decrypter - decrypts the traffic and forwards it into a
// bufferer

class traffic_decrypter {
public:
    traffic_decrypter(unique_fd fd, Crypto::WPA2Decrypter wpa2d, 
      Crypto::WEPDecrypter wepd)
    : bufferer(std::move(fd), std::move(wpa2d), std::move(wepd))
    {
        
    }
    
    void decrypt_traffic(Sniffer &sniffer) 
    {
        using std::placeholders::_1;
        
        bufferer.run();
        sniffer.sniff_loop(std::bind(&traffic_decrypter::callback, this, _1));
        bufferer.stop_running();
    }
private:
    bool callback(PDU &pdu) 
    {
        if(pdu.find_pdu<Dot11>() == nullptr && pdu.find_pdu<RadioTap>() == nullptr)
            throw std::runtime_error("Expected an 802.11 interface in monitor mode");
        bufferer.add_packet(
            packet_buffer::unique_pdu(pdu.clone())
        );
        return running;
    }

    packet_buffer bufferer;
};


// if_up - brings the interface up

void if_up(const char *name) {
    int err, fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
   
    if( (err = ioctl(fd, SIOCGIFFLAGS, (void *) &ifr)) < 0 ) {
        close(fd);
        std::cout << strerror(errno) << std::endl;
        throw std::runtime_error("Failed get flags");
    }
   
    ifr.ifr_flags |= IFF_UP|IFF_RUNNING;
   
    if( (err = ioctl(fd, SIOCSIFFLAGS, (void *) &ifr)) < 0 ) {
        close(fd);
        std::cout << strerror(errno) << std::endl;
        throw std::runtime_error("Failed to bring the interface up");
    }
}

// create_tap_dev - creates a tap device

std::tuple<unique_fd, std::string> create_tap_dev() {
    struct ifreq ifr;
    int err;
    char clonedev[] = "/dev/net/tun";
    unique_fd fd = open(clonedev, O_RDWR);

    if(!fd)
        throw std::runtime_error("Failed to open /dev/net/tun");

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;   

    if( (err = ioctl(*fd, TUNSETIFF, (void *) &ifr)) < 0 )
        throw std::runtime_error("Failed to create tap device");

    return std::make_tuple(std::move(fd), ifr.ifr_name);
}

// sig_handler - SIGINT handler, so we can release resources appropriately
void sig_handler(int) 
{
    if(running) {
        std::cout << "Stopping the sniffer...\n";
        running = false; 
    }
}


typedef std::tuple<
            Crypto::WPA2Decrypter, 
            Crypto::WEPDecrypter
        > decrypter_tuple;

// Creates a traffic_decrypter and puts it to work
void decrypt_traffic(unique_fd fd, const std::string &iface, decrypter_tuple tup) 
{
    Sniffer sniffer(iface, 2500, false);
    traffic_decrypter decrypter(
        std::move(fd), 
        std::move(std::get<0>(tup)), 
        std::move(std::get<1>(tup))
    );
    decrypter.decrypt_traffic(sniffer);
}

// parses the arguments and returns a tuple (WPA2Decrypter, WEPDectyper)
// throws if arguments are invalid
decrypter_tuple parse_args(const std::vector<std::string> &args) 
{
    decrypter_tuple tup;
    for(const auto &i : args) {
        if(i.find("wpa:") == 0) {
            auto pos = i.find(':', 4);
            if(pos != std::string::npos) {
                std::get<0>(tup).add_ap_data(
                    i.substr(pos + 1), // psk
                    i.substr(4, pos - 4) // ssid
                );
            }
            else {
                throw std::invalid_argument("Invalid decryption data");
            }
        }
        else if(i.find("wep:") == 0) {
            const auto sz = std::string("00:00:00:00:00:00").size();
            if(sz + 4 >= i.size())
                throw std::invalid_argument("Invalid decryption data");
            std::get<1>(tup).add_password(
                i.substr(5, sz), // bssid
                i.substr(5 + sz) // passphrase
            );
        }
        else {
            throw std::invalid_argument("Expected decription data.");
        }
    }
    return tup;
}

void print_usage(const char *arg0)
{
    std::cout << "Usage: " << arg0 << " <interface> DECRYPTION_DATA [DECRYPTION_DATA] [...]\n\n";
    std::cout << "Where DECRYPTION_DATA can be: \n";
    std::cout << "\twpa:SSID:PSK - to specify WPA2(AES or TKIP) decryption data.\n";
    std::cout << "\twep:BSSID:KEY - to specify WEP decryption data.\n\n";
    std::cout << "Examples:\n";
    std::cout << "\t" << arg0 << " wlan0 wpa:MyAccessPoint:some_password\n";
    std::cout << "\t" << arg0 << " mon0 wep:00:01:02:03:04:05:blahbleehh\n";
    exit(1);
}

int main(int argc, char *argv[]) 
{
    if(argc < 3) {
        print_usage(*argv);
    }
    try {
        auto decrypters = parse_args(std::vector<std::string>(argv + 2, argv + argc));
        std::string dev_name;
        unique_fd fd;
        std::tie(fd, dev_name) = create_tap_dev();
        std::cout << "Using device: " << dev_name << std::endl;
        if_up(dev_name.c_str());
        std::cout << "Device is up.\n";
        signal(SIGINT, sig_handler);
        running = true;
        decrypt_traffic(std::move(fd), argv[1], std::move(decrypters));
        std::cout << "Done\n";
    }
    catch(std::invalid_argument& ex) {
        std::cout << "[-] " << ex.what() << std::endl;
        print_usage(*argv);
    }
    catch(std::exception& ex) {
        std::cout << "[-] " << ex.what() << std::endl;
    }
}
