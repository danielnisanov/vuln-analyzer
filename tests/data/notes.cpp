#include <iostream>
#include <vector>
#include <cstring>
#include <limits>
#include <cstdint>
#include <algorithm>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <map>

using std::cin;
using std::cout;
using std::endl;
using std::size_t;

struct Note {
    uint32_t len;
    char *buf;
};

static std::vector<Note *> g_notes;

void sanitizeInput(std::string &s) {
    s.erase(std::remove(s.begin(), s.end(), '\n'), s.end());
    s.erase(std::remove(s.begin(), s.end(), '\r'), s.end());
}

std::string getLine(const std::string &prompt) {
    cout << prompt;
    std::string line;
    std::getline(cin, line);
    sanitizeInput(line);
    return line;
}

void logAction(const std::string &action) {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::localtime(&t);
    cout << "[LOG " << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] " << action << endl;
}

bool safeIndex(size_t idx) {
    return idx < g_notes.size() && g_notes[idx] != nullptr;
}

std::map<std::string, size_t> secureStats = {
    {"notes_created", 0},
    {"notes_deleted", 0},
    {"total_alloc", 0},
    {"total_freed", 0},
};

// ---------------- Function Declarations ----------------
void addNote();
void viewNote();
void deleteNote();
void processBuffer();
void viewDeletedNote();
void showSafeStats();
void showNoteSummary();
void clearAllNotes();

void banner() {
    cout << "===============================\n";
    cout << "  VULN APP DEMO (C++)\n";
    cout << "===============================\n";
}

void menu() {
    cout << "\nMenu:\n";
    cout << " 1. Add note (integer overflow)\n";
    cout << " 2. View note\n";
    cout << " 3. Delete note\n";
    cout << " 4. Process buffer (heap-overflow)\n";
    cout << " 5. View deleted note (use-after-free)\n";
    cout << " 6. Show statistics (safe code)\n";
    cout << " 7. Note summary (safe code)\n";
    cout << " 8. Clear all notes (safe code)\n";
    cout << " 0. Exit\n";
    cout << "> ";
}

int main() {
    banner();
    while (true) {
        menu();
        int choice = -1;
        if (!(cin >> choice)) {
            cout << "Invalid input—exiting.\n";
            break;
        }
        cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        switch (choice) {
            case 1: addNote(); break;
            case 2: viewNote(); break;
            case 3: deleteNote(); break;
            case 4: processBuffer(); break;
            case 5: viewDeletedNote(); break;
            case 6: showSafeStats(); break;
            case 7: showNoteSummary(); break;
            case 8: clearAllNotes(); break;
            case 0: cout << "Goodbye!\n"; return 0;
            default: cout << "Unknown option.\n"; break;
        }
    }
    return 0;
}

void addNote() {
    uint32_t len = 0;
    cout << "Enter note length: ";
    cin >> len;

    uint32_t allocSize = len * 2;
    char *buf = new char[allocSize];
    cout << "Enter note content (" << len << " bytes expected):\n";

    cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    cin.read(buf, len);

    Note *n = new Note{len, buf};
    g_notes.push_back(n);

    secureStats["notes_created"]++;
    secureStats["total_alloc"] += allocSize;
    logAction("Added note of length " + std::to_string(len));

    cout << "Note added at index " << g_notes.size() - 1 << "\n";
}

// ---------------- Basic helpers ----------------
size_t promptIndex() {
    cout << "Enter note index: ";
    size_t idx = 0;
    cin >> idx;
    return idx;
}

void viewNote() {
    size_t idx = promptIndex();
    if (!safeIndex(idx)) {
        cout << "Invalid index.\n";
        return;
    }
    Note *n = g_notes[idx];
    cout << "[Note " << idx << "] (len=" << n->len << "):\n";
    cout.write(n->buf, n->len);
    cout << "\n";
}

void deleteNote() {
    size_t idx = promptIndex();
    if (!safeIndex(idx)) {
        cout << "Invalid index.\n";
        return;
    }
    Note *n = g_notes[idx];
    delete[] n->buf;
    delete n;
    g_notes[idx] = nullptr;

    secureStats["notes_deleted"]++;
    secureStats["total_freed"]++;
    logAction("Deleted note at index " + std::to_string(idx));

    cout << "Note deleted.\n";
}

void processBuffer() {
    const size_t FIXED = 64;
    char *tmp = new char[FIXED];

    cout << "Enter data to process (any length):\n";
    std::string line;
    std::getline(cin, line);

    std::memcpy(tmp, line.data(), line.size());

    cout << "Data processed: " << tmp << "\n";
    delete[] tmp;
}

void viewDeletedNote() {
    static size_t cachedIdx = SIZE_MAX;
    if (cachedIdx == SIZE_MAX) {
        cout << "Caching a deleted note index first...\n";
        cout << "Delete a note (option 3) and then use this option again.\n";
        cachedIdx = promptIndex();
        return;
    }

    if (cachedIdx >= g_notes.size()) {
        cout << "Index out of range. Resetting cache.\n";
        cachedIdx = SIZE_MAX;
        return;
    }

    Note *n = g_notes[cachedIdx];
    cout << "Attempting to display deleted note at index " << cachedIdx << "...\n";
    if (n) {
        cout.write(n->buf, n->len);
        cout << "\n";
    } else {
        cout << "[dangling pointer] " << n << "\n";
    }
}

void showSafeStats() {
    size_t count = 0;
    size_t totalBytes = 0;
    for (const auto *n : g_notes) {
        if (n) {
            ++count;
            totalBytes += n->len;
        }
    }
    cout << "\nStatistics:\n";
    cout << " - Active notes: " << count << "\n";
    cout << " - Total characters stored: " << totalBytes << "\n";
    for (const auto &[key, val] : secureStats) {
        cout << " - " << key << ": " << val << "\n";
    }
}

void showNoteSummary() {
    cout << "\nNote Summary:\n";
    for (size_t i = 0; i < g_notes.size(); ++i) {
        if (g_notes[i]) {
            cout << " - Note " << i << ": length = " << g_notes[i]->len << "\n";
        }
    }
}

void clearAllNotes() {
    for (auto &note : g_notes) {
        if (note) {
            delete[] note->buf;
            delete note;
        }
    }
    g_notes.clear();
    logAction("Cleared all notes");
    cout << "All notes cleared.\n";
}
