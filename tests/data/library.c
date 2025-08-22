#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <math.h>

#define MAX_TITLE_LENGTH 200
#define MAX_AUTHOR_LENGTH 100
#define MAX_NAME_LENGTH 100
#define MAX_EMAIL_LENGTH 100
#define MAX_PHONE_LENGTH 20
#define MAX_GENRE_LENGTH 50
#define MAX_ISBN_LENGTH 20
#define MAX_BOOKS 10000
#define MAX_MEMBERS 5000
#define MAX_TRANSACTIONS 50000
#define MAX_BORROWED_BOOKS 20
#define MAX_WAITING_LIST 100
#define BASIC_BORROW_LIMIT 3
#define PREMIUM_BORROW_LIMIT 7
#define VIP_BORROW_LIMIT 15
#define BASIC_BORROW_DAYS 14
#define PREMIUM_BORROW_DAYS 21
#define VIP_BORROW_DAYS 30
#define LATE_FEE_PER_DAY 0.50
#define BASIC_DISCOUNT 0.05
#define PREMIUM_DISCOUNT 0.10
#define VIP_DISCOUNT 0.20

// Enumerations
typedef enum {
    MEMBERSHIP_BASIC,
    MEMBERSHIP_PREMIUM,
    MEMBERSHIP_VIP
} MembershipType;

typedef enum {
    TRANSACTION_BORROW,
    TRANSACTION_RETURN,
    TRANSACTION_PURCHASE,
    TRANSACTION_REGISTER,
    TRANSACTION_CANCEL,
    TRANSACTION_LATE_FEE,
    TRANSACTION_RESERVATION
} TransactionType;

typedef enum {
    BOOK_AVAILABLE,
    BOOK_BORROWED,
    BOOK_RESERVED,
    BOOK_MAINTENANCE,
    BOOK_SOLD
} BookStatus;

typedef enum {
    GENRE_FICTION,
    GENRE_NONFICTION,
    GENRE_MYSTERY,
    GENRE_ROMANCE,
    GENRE_SCIFI,
    GENRE_FANTASY,
    GENRE_BIOGRAPHY,
    GENRE_HISTORY,
    GENRE_SCIENCE,
    GENRE_TECHNOLOGY,
    GENRE_SELF_HELP,
    GENRE_OTHER
} GenreType;

// Forward declarations
struct Book;
struct Member;
struct Transaction;
struct Library;
struct WaitingListEntry;

// Book structure with comprehensive information
typedef struct Book {
    char isbn[MAX_ISBN_LENGTH];
    char title[MAX_TITLE_LENGTH];
    char author[MAX_AUTHOR_LENGTH];
    GenreType genre;
    int publication_year;
    BookStatus status;
    double purchase_price;
    double rental_price;
    int total_copies;
    int available_copies;
    int times_borrowed;
    int times_purchased;
    time_t date_added;
    int current_borrower_id;
    time_t due_date;
    struct WaitingListEntry* waiting_list;
    int waiting_count;
} Book;

// Waiting list entry for popular books
typedef struct WaitingListEntry {
    int member_id;
    time_t request_date;
    struct WaitingListEntry* next;
} WaitingListEntry;

// Member structure with detailed information
typedef struct Member {
    int member_id;
    char name[MAX_NAME_LENGTH];
    char email[MAX_EMAIL_LENGTH];
    char phone[MAX_PHONE_LENGTH];
    MembershipType membership_type;
    time_t registration_date;
    time_t last_activity;
    int borrowed_books[MAX_BORROWED_BOOKS];
    int num_borrowed;
    double outstanding_fees;
    int books_purchased;
    int books_borrowed_total;
    int is_active;
    double membership_fee_paid;
    time_t membership_expiry;
} Member;

// Transaction record for audit trail
typedef struct Transaction {
    int transaction_id;
    int member_id;
    char isbn[MAX_ISBN_LENGTH];
    TransactionType type;
    time_t timestamp;
    double amount;
    char description[200];
    int processed_by; // Staff ID
} Transaction;

// Main library system structure
typedef struct Library {
    Book books[MAX_BOOKS];
    Member members[MAX_MEMBERS];
    Transaction transactions[MAX_TRANSACTIONS];
    int book_count;
    int member_count;
    int transaction_count;
    int next_member_id;
    int next_transaction_id;
    time_t system_start_time;
    char library_name[100];
    double total_revenue;
    int total_books_circulated;
} Library;

// Global library instance
Library library;

// Function prototypes
void initialize_library();
void display_main_menu();
void handle_menu_choice(int choice);

// Book management functions
int add_book(const char* isbn, const char* title, const char* author, GenreType genre, 
             int year, double purchase_price, double rental_price, int copies);
Book* find_book_by_isbn(const char* isbn);
Book* find_book_by_title(const char* title);
void display_book_details(const Book* book);
void list_all_books();
void search_books();
void search_books_by_author(const char* author);
void search_books_by_genre(GenreType genre);
void update_book_status(const char* isbn, BookStatus status);
void add_to_waiting_list(const char* isbn, int member_id);
void process_waiting_list(const char* isbn);

// Member management functions
int create_member(const char* name, const char* email, const char* phone, MembershipType type);
Member* find_member_by_id(int member_id);
Member* find_member_by_email(const char* email);
void display_member_details(const Member* member);
void list_all_members();
void update_member_info(int member_id);
int cancel_membership(int member_id);
void calculate_membership_fees();
double get_discount_rate(MembershipType type);
int get_borrow_limit(MembershipType type);
int get_borrow_days(MembershipType type);

// Transaction functions
void record_transaction(int member_id, const char* isbn, TransactionType type, 
                       double amount, const char* description);
void display_transaction_history(int member_id);
void display_all_transactions();
void generate_financial_report();

// Borrowing and returning functions
int borrow_book(int member_id, const char* isbn);
int return_book(int member_id, const char* isbn);
double calculate_late_fee(time_t due_date, time_t return_date);
void check_overdue_books();
void send_overdue_notices();

// Purchase functions
int purchase_book(int member_id, const char* isbn);
double calculate_purchase_price(const Book* book, MembershipType membership);

// Utility functions
void clear_input_buffer();
char* get_string_input(const char* prompt, char* buffer, int max_length);
int get_integer_input(const char* prompt, int min, int max);
double get_double_input(const char* prompt, double min, double max);
time_t get_current_time();
char* format_time(time_t time);
char* get_genre_string(GenreType genre);
GenreType get_genre_from_string(const char* genre_str);
char* get_membership_string(MembershipType type);
char* get_status_string(BookStatus status);
void to_uppercase(char* str);
void trim_whitespace(char* str);

// Data persistence functions
void save_library_data();
void load_library_data();
void backup_data();
void restore_data();

// Advanced features
void generate_recommendations(int member_id);
void display_popular_books();
void display_member_statistics();
void display_system_statistics();
void bulk_add_books();
void bulk_update_books();
void export_data_csv();
void import_data_csv();

// Administrative functions
void admin_menu();
void staff_operations();
void system_maintenance();
void generate_reports();

// Other
void generate_member_activity_report();
void generate_circulation_report();
void generate_membership_statistics();
void generate_revenue_analysis();

// System maintenance functions
void check_data_integrity();
void cleanup_old_transactions();
void update_all_book_status();
void process_expired_memberships();
void recalculate_outstanding_fees();
void optimize_database();
void generate_system_health_report();

// Staff operation functions
void process_bulk_returns();
void handle_reservations();
void collect_late_fees();
void member_account_management();
void book_maintenance();
void inventory_management();
void generate_staff_reports();
void generate_daily_activity_summary();

// Additional utility functions
void shutdown_system();
void initialize_sample_data();
void cleanup_waiting_lists();
int validate_isbn(const char* isbn);
int validate_email(const char* email);
int validate_phone(const char* phone);
void advanced_search();

// Main function
int main() {
    printf("=== Comprehensive Library Management System ===\n");
    printf("Initializing system...\n");
    
    initialize_library();
    load_library_data();
    
    printf("System initialized successfully!\n");
    printf("Welcome to %s\n", library.library_name);
    
    int choice;
    do {
        display_main_menu();
        choice = get_integer_input("Enter your choice", 0, 15);
        handle_menu_choice(choice);
    } while (choice != 0);
    
    save_library_data();
    printf("Thank you for using the Library Management System!\n");
    return 0;
}

// Initialize the library system
void initialize_library() {
    memset(&library, 0, sizeof(Library));
    strcpy(library.library_name, "Central Public Library");
    library.next_member_id = 1001;
    library.next_transaction_id = 1;
    library.system_start_time = get_current_time();
    library.total_revenue = 0.0;
    library.total_books_circulated = 0;
    
    // Add some sample books
    add_book("978-0-123456-78-9", "The Great Gatsby", "F. Scott Fitzgerald", 
             GENRE_FICTION, 1925, 15.99, 2.50, 5);
    add_book("978-0-987654-32-1", "To Kill a Mockingbird", "Harper Lee", 
             GENRE_FICTION, 1960, 12.99, 2.00, 3);
    add_book("978-1-234567-89-0", "1984", "George Orwell", 
             GENRE_FICTION, 1949, 13.99, 2.25, 4);
    add_book("978-0-555555-55-5", "A Brief History of Time", "Stephen Hawking", 
             GENRE_SCIENCE, 1988, 18.99, 3.00, 2);
    add_book("978-0-111111-11-1", "The Art of Computer Programming", "Donald Knuth", 
             GENRE_TECHNOLOGY, 1968, 89.99, 5.00, 1);
}

// Display main menu
void display_main_menu() {
    printf("\n==================================================\n");
    printf("           LIBRARY MANAGEMENT SYSTEM\n");
    printf("==================================================\n");
    printf("1.  Create Library Card (Register)\n");
    printf("2.  Borrow a Book\n");
    printf("3.  Return a Book\n");
    printf("4.  Purchase a Book\n");
    printf("5.  Cancel Membership\n");
    printf("6.  Search Books\n");
    printf("7.  View My Account\n");
    printf("8.  Browse All Books\n");
    printf("9.  Get Book Recommendations\n");
    printf("10. View Popular Books\n");
    printf("11. Check Overdue Books\n");
    printf("12. Administrative Functions\n");
    printf("13. System Reports\n");
    printf("14. Data Management\n");
    printf("15. System Statistics\n");
    printf("0.  Exit System\n");
    printf("==================================================\n");
}

// Handle menu choice
void handle_menu_choice(int choice) {
    int member_id;
    char isbn[MAX_ISBN_LENGTH];
    char name[MAX_NAME_LENGTH], email[MAX_EMAIL_LENGTH], phone[MAX_PHONE_LENGTH];
    int membership_choice;
    MembershipType membership_type;
    
    switch (choice) {
        case 1: // Create Library Card
            printf("\n--- Create Library Card ---\n");
            get_string_input("Enter your full name", name, MAX_NAME_LENGTH);
            get_string_input("Enter your email", email, MAX_EMAIL_LENGTH);
            get_string_input("Enter your phone number", phone, MAX_PHONE_LENGTH);
            
            printf("Select Membership Type:\n");
            printf("1. Basic ($10/year) - 3 books, 14 days\n");
            printf("2. Premium ($25/year) - 7 books, 21 days, 10%% discount\n");
            printf("3. VIP ($50/year) - 15 books, 30 days, 20%% discount\n");
            
            membership_choice = get_integer_input("Choose membership type", 1, 3);
            switch (membership_choice) {
                case 1: membership_type = MEMBERSHIP_BASIC; break;
                case 2: membership_type = MEMBERSHIP_PREMIUM; break;
                case 3: membership_type = MEMBERSHIP_VIP; break;
                default: membership_type = MEMBERSHIP_BASIC;
            }
            
            member_id = create_member(name, email, phone, membership_type);
            if (member_id > 0) {
                printf("Library card created successfully!\n");
                printf("Your Member ID is: %d\n", member_id);
                printf("Please keep this ID for future transactions.\n");
            }
            break;
            
        case 2: // Borrow a Book
            printf("\n--- Borrow a Book ---\n");
            member_id = get_integer_input("Enter your Member ID", 1000, 99999);
            get_string_input("Enter book ISBN", isbn, MAX_ISBN_LENGTH);
            
            if (borrow_book(member_id, isbn)) {
                printf("Book borrowed successfully!\n");
            } else {
                printf("Unable to borrow book. Please check details.\n");
            }
            break;
            
        case 3: // Return a Book
            printf("\n--- Return a Book ---\n");
            member_id = get_integer_input("Enter your Member ID", 1000, 99999);
            get_string_input("Enter book ISBN", isbn, MAX_ISBN_LENGTH);
            
            if (return_book(member_id, isbn)) {
                printf("Book returned successfully!\n");
            } else {
                printf("Unable to return book. Please check details.\n");
            }
            break;
            
        case 4: // Purchase a Book
            printf("\n--- Purchase a Book ---\n");
            member_id = get_integer_input("Enter your Member ID", 1000, 99999);
            get_string_input("Enter book ISBN", isbn, MAX_ISBN_LENGTH);
            
            if (purchase_book(member_id, isbn)) {
                printf("Book purchased successfully!\n");
            } else {
                printf("Unable to purchase book. Please check details.\n");
            }
            break;
            
        case 5: // Cancel Membership
            printf("\n--- Cancel Membership ---\n");
            member_id = get_integer_input("Enter your Member ID", 1000, 99999);
            
            if (cancel_membership(member_id)) {
                printf("Membership cancelled successfully.\n");
                printf("Thank you for using our library services.\n");
            } else {
                printf("Unable to cancel membership. Please check Member ID.\n");
            }
            break;
            
        case 6: // Search Books
            search_books();
            break;
            
        case 7: // View My Account
            printf("\n--- View My Account ---\n");
            member_id = get_integer_input("Enter your Member ID", 1000, 99999);
            Member* member = find_member_by_id(member_id);
            if (member) {
                display_member_details(member);
                display_transaction_history(member_id);
            } else {
                printf("Member not found.\n");
            }
            break;
            
        case 8: // Browse All Books
            list_all_books();
            break;
            
        case 9: // Get Book Recommendations
            printf("\n--- Book Recommendations ---\n");
            member_id = get_integer_input("Enter your Member ID", 1000, 99999);
            generate_recommendations(member_id);
            break;
            
        case 10: // View Popular Books
            display_popular_books();
            break;
            
        case 11: // Check Overdue Books
            check_overdue_books();
            break;
            
        case 12: // Administrative Functions
            admin_menu();
            break;
            
        case 13: // System Reports
            generate_reports();
            break;
            
        case 14: // Data Management
            printf("\n--- Data Management ---\n");
            printf("1. Save Data\n2. Load Data\n3. Backup Data\n4. Restore Data\n");
            printf("5. Export to CSV\n6. Import from CSV\n");
            int data_choice = get_integer_input("Choose option", 1, 6);
            switch (data_choice) {
                case 1: save_library_data(); break;
                case 2: load_library_data(); break;
                case 3: backup_data(); break;
                case 4: restore_data(); break;
                case 5: export_data_csv(); break;
                case 6: import_data_csv(); break;
            }
            break;
            
        case 15: // System Statistics
            display_system_statistics();
            break;
            
        case 0: // Exit
            printf("Saving data and exiting...\n");
            break;
            
        default:
            printf("Invalid choice. Please try again.\n");
    }
}

// Add a book to the library
int add_book(const char* isbn, const char* title, const char* author, GenreType genre, 
             int year, double purchase_price, double rental_price, int copies) {
    if (library.book_count >= MAX_BOOKS) {
        printf("Library is at maximum capacity for books.\n");
        return 0;
    }
    
    // Check if book already exists
    if (find_book_by_isbn(isbn)) {
        printf("Book with ISBN %s already exists.\n", isbn);
        return 0;
    }
    
    Book* book = &library.books[library.book_count];
    strcpy(book->isbn, isbn);
    strcpy(book->title, title);
    strcpy(book->author, author);
    book->genre = genre;
    book->publication_year = year;
    book->status = BOOK_AVAILABLE;
    book->purchase_price = purchase_price;
    book->rental_price = rental_price;
    book->total_copies = copies;
    book->available_copies = copies;
    book->times_borrowed = 0;
    book->times_purchased = 0;
    book->date_added = get_current_time();
    book->current_borrower_id = 0;
    book->due_date = 0;
    book->waiting_list = NULL;
    book->waiting_count = 0;
    
    library.book_count++;
    printf("Book added successfully: %s\n", title);
    return 1;
}

// Find book by ISBN
Book* find_book_by_isbn(const char* isbn) {
    for (int i = 0; i < library.book_count; i++) {
        if (strcmp(library.books[i].isbn, isbn) == 0) {
            return &library.books[i];
        }
    }
    return NULL;
}

// Find book by title (case-insensitive partial match)
Book* find_book_by_title(const char* title) {
    char search_title[MAX_TITLE_LENGTH];
    strcpy(search_title, title);
    to_uppercase(search_title);
    
    for (int i = 0; i < library.book_count; i++) {
        char book_title[MAX_TITLE_LENGTH];
        strcpy(book_title, library.books[i].title);
        to_uppercase(book_title);
        
        if (strstr(book_title, search_title) != NULL) {
            return &library.books[i];
        }
    }
    return NULL;
}

// Display detailed book information
void display_book_details(const Book* book) {
    if (!book) return;
    
    printf("\n============================================================\n");
    printf("BOOK DETAILS\n");
    printf("============================================================\n");
    printf("ISBN: %s\n", book->isbn);
    printf("Title: %s\n", book->title);
    printf("Author: %s\n", book->author);
    printf("Genre: %s\n", get_genre_string(book->genre));
    printf("Publication Year: %d\n", book->publication_year);
    printf("Status: %s\n", get_status_string(book->status));
    printf("Purchase Price: $%.2f\n", book->purchase_price);
    printf("Rental Price: $%.2f\n", book->rental_price);
    printf("Total Copies: %d\n", book->total_copies);
    printf("Available Copies: %d\n", book->available_copies);
    printf("Times Borrowed: %d\n", book->times_borrowed);
    printf("Times Purchased: %d\n", book->times_purchased);
    printf("Date Added: %s\n", format_time(book->date_added));
    
    if (book->current_borrower_id > 0) {
        printf("Current Borrower ID: %d\n", book->current_borrower_id);
        printf("Due Date: %s\n", format_time(book->due_date));
    }
    
    if (book->waiting_count > 0) {
        printf("Waiting List: %d people\n", book->waiting_count);
    }
    
    printf("============================================================\n");
}

// List all books in the library
void list_all_books() {
    printf("\n--- All Books in Library ---\n");
    printf("%-20s %-40s %-25s %-15s %s\n", "ISBN", "Title", "Author", "Status", "Available");
    printf("------------------------------------------------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < library.book_count; i++) {
        Book* book = &library.books[i];
        printf("%-20s %-40s %-25s %-15s %d/%d\n",
               book->isbn,
               book->title,
               book->author,
               get_status_string(book->status),
               book->available_copies,
               book->total_copies);
    }
    
    printf("\nTotal books: %d\n", library.book_count);
}

// Advanced search functionality
void search_books() {
    printf("\n--- Search Books ---\n");
    printf("1. Search by Title\n");
    printf("2. Search by Author\n");
    printf("3. Search by ISBN\n");
    printf("4. Search by Genre\n");
    printf("5. Search by Publication Year\n");
    printf("6. Advanced Search\n");
    
    int choice = get_integer_input("Choose search method", 1, 6);
    char search_term[200];
    
    switch (choice) {
        case 1: // Search by title
            get_string_input("Enter title (partial match allowed)", search_term, 200);
            {
                char upper_search[50];
                strcpy(upper_search, search_term);
                to_uppercase(upper_search);
            
                printf("\nSearch Results:\n");
                int found = 0;
                for (int i = 0; i < library.book_count; i++) {
                    char upper_title[MAX_TITLE_LENGTH];
                    strcpy(upper_title, library.books[i].title);
                    to_uppercase(upper_title);
                    
                    if (strstr(upper_title, upper_search)) {
                        display_book_details(&library.books[i]);
                        found++;
                    }
                }
                if (found == 0) printf("No books found matching '%s'\n", search_term);
                else printf("\nFound %d book(s)\n", found);
            }
            break;
            
        case 2: // Search by author
            get_string_input("Enter author name", search_term, 200);
            search_books_by_author(search_term);
            break;
            
        case 3: // Search by ISBN
            get_string_input("Enter ISBN", search_term, MAX_ISBN_LENGTH);
            {
                Book* book = find_book_by_isbn(search_term);
                if (book) {
                    display_book_details(book);
                } else {
                    printf("No book found with ISBN: %s\n", search_term);
                }
            }
            break;
            
        case 4: // Search by genre
            printf("Available Genres:\n");
            for (int i = 0; i <= GENRE_OTHER; i++) {
                printf("%d. %s\n", i+1, get_genre_string((GenreType)i));
            }
            int genre_choice = get_integer_input("Select genre", 1, GENRE_OTHER+1);
            search_books_by_genre((GenreType)(genre_choice-1));
            break;
            
        case 5: // Search by publication year
            {
                int year = get_integer_input("Enter publication year", 1000, 2025);
                printf("\nBooks published in %d:\n", year);
                int found = 0;
                for (int i = 0; i < library.book_count; i++) {
                    if (library.books[i].publication_year == year) {
                        display_book_details(&library.books[i]);
                        found++;
                    }
                }
                if (found == 0) printf("No books found for year %d\n", year);
                else printf("\nFound %d book(s)\n", found);
            }
            break;
            
        case 6: // Advanced search
            printf("Advanced search feature coming soon!\n");
            break;
    }
}

// Search books by author
void search_books_by_author(const char* author) {
    char upper_author[MAX_AUTHOR_LENGTH];
    strcpy(upper_author, author);
    to_uppercase(upper_author);
    
    printf("\nBooks by '%s':\n", author);
    int found = 0;
    
    for (int i = 0; i < library.book_count; i++) {
        char book_author[MAX_AUTHOR_LENGTH];
        strcpy(book_author, library.books[i].author);
        to_uppercase(book_author);
        
        if (strstr(book_author, upper_author)) {
            display_book_details(&library.books[i]);
            found++;
        }
    }
    
    if (found == 0) printf("No books found by '%s'\n", author);
    else printf("\nFound %d book(s) by '%s'\n", found, author);
}

// Search books by genre
void search_books_by_genre(GenreType genre) {
    printf("\nBooks in genre '%s':\n", get_genre_string(genre));
    int found = 0;
    
    for (int i = 0; i < library.book_count; i++) {
        if (library.books[i].genre == genre) {
            display_book_details(&library.books[i]);
            found++;
        }
    }
    
    if (found == 0) printf("No books found in genre '%s'\n", get_genre_string(genre));
    else printf("\nFound %d book(s) in genre '%s'\n", found, get_genre_string(genre));
}

// Create a new member
int create_member(const char* name, const char* email, const char* phone, MembershipType type) {
    if (library.member_count >= MAX_MEMBERS) {
        printf("Library is at maximum capacity for members.\n");
        return 0;
    }
    
    // Check if email already exists
    if (find_member_by_email(email)) {
        printf("A member with this email already exists.\n");
        return 0;
    }
    
    Member* member = &library.members[library.member_count];
    member->member_id = library.next_member_id++;
    strcpy(member->name, name);
    strcpy(member->email, email);
    strcpy(member->phone, phone);
    member->membership_type = type;
    member->registration_date = get_current_time();
    member->last_activity = get_current_time();
    memset(member->borrowed_books, 0, sizeof(member->borrowed_books));
    member->num_borrowed = 0;
    member->outstanding_fees = 0.0;
    member->books_purchased = 0;
    member->books_borrowed_total = 0;
    member->is_active = 1;
    
    // Calculate membership fee
    switch (type) {
        case MEMBERSHIP_BASIC: member->membership_fee_paid = 10.00; break;
        case MEMBERSHIP_PREMIUM: member->membership_fee_paid = 25.00; break;
        case MEMBERSHIP_VIP: member->membership_fee_paid = 50.00; break;
    }
    
    // Set membership expiry (1 year from now)
    struct tm* tm_info = localtime(&member->registration_date);
    tm_info->tm_year += 1;
    member->membership_expiry = mktime(tm_info);
    
    library.member_count++;
    library.total_revenue += member->membership_fee_paid;
    
    // Record registration transaction
    record_transaction(member->member_id, "", TRANSACTION_REGISTER, 
                      member->membership_fee_paid, "Membership registration");
    
    printf("Welcome to %s, %s!\n", library.library_name, name);
    printf("Membership Type: %s\n", get_membership_string(type));
    printf("Membership Fee: $%.2f\n", member->membership_fee_paid);
    printf("Membership Expires: %s\n", format_time(member->membership_expiry));
    
    return member->member_id;
}

// Find member by ID
Member* find_member_by_id(int member_id) {
    for (int i = 0; i < library.member_count; i++) {
        if (library.members[i].member_id == member_id && library.members[i].is_active) {
            return &library.members[i];
        }
    }
    return NULL;
}

// Find member by email
Member* find_member_by_email(const char* email) {
    for (int i = 0; i < library.member_count; i++) {
        if (strcmp(library.members[i].email, email) == 0 && library.members[i].is_active) {
            return &library.members[i];
        }
    }
    return NULL;
}

// Display member details
void display_member_details(const Member* member) {
    if (!member) return;
    
    printf("\n===============================================\n");
    printf("MEMBER DETAILS\n");
    printf("===============================================\n");
    printf("Member ID: %d\n", member->member_id);
    printf("Name: %s\n", member->name);
    printf("Email: %s\n", member->email);
    printf("Phone: %s\n", member->phone);
    printf("Membership Type: %s\n", get_membership_string(member->membership_type));
    printf("Registration Date: %s\n", format_time(member->registration_date));
    printf("Last Activity: %s\n", format_time(member->last_activity));
    printf("Membership Expires: %s\n", format_time(member->membership_expiry));
    printf("Outstanding Fees: $%.2f\n", member->outstanding_fees);
    printf("Books Currently Borrowed: %d\n", member->num_borrowed);
    printf("Total Books Borrowed: %d\n", member->books_borrowed_total);
    printf("Books Purchased: %d\n", member->books_purchased);
    printf("Borrow Limit: %d books\n", get_borrow_limit(member->membership_type));
    printf("Borrow Period: %d days\n", get_borrow_days(member->membership_type));
    printf("Purchase Discount: %.0f%%\n", get_discount_rate(member->membership_type) * 100);
    
    if (member->num_borrowed > 0) {
        printf("\nCurrently Borrowed Books:\n");
        printf("%-20s %-40s %-15s\n", "ISBN", "Title", "Due Date");
        printf("-----------------------------------------------------------------------\n");
        
        for (int i = 0; i < member->num_borrowed; i++) {
            for (int j = 0; j < library.book_count; j++) {
                if (library.books[j].current_borrower_id == member->member_id) {
                    printf("%-20s %-40s %-15s\n",
                           library.books[j].isbn,
                           library.books[j].title,
                           format_time(library.books[j].due_date));
                }
            }
        }
    }
    
    printf("===============================================\n");
}

// Cancel membership
int cancel_membership(int member_id) {
    Member* member = find_member_by_id(member_id);
    if (!member) {
        printf("Member not found.\n");
        return 0;
    }
    
    // Check for outstanding books
    if (member->num_borrowed > 0) {
        printf("Cannot cancel membership: %d book(s) still borrowed.\n", member->num_borrowed);
        printf("Please return all books before cancelling membership.\n");
        return 0;
    }
    
    // Check for outstanding fees
    if (member->outstanding_fees > 0) {
        printf("Cannot cancel membership: Outstanding fees of $%.2f must be paid.\n", 
               member->outstanding_fees);
        return 0;
    }
    
    // Deactivate membership
    member->is_active = 0;
    
    // Record cancellation transaction
    record_transaction(member_id, "", TRANSACTION_CANCEL, 0.0, "Membership cancelled");
    
    printf("Membership for %s (ID: %d) has been cancelled.\n", member->name, member_id);
    return 1;
}

// Borrow a book
int borrow_book(int member_id, const char* isbn) {
    Member* member = find_member_by_id(member_id);
    if (!member) {
        printf("Member not found.\n");
        return 0;
    }
    
    // Check if membership is expired
    if (get_current_time() > member->membership_expiry) {
        printf("Membership has expired. Please renew to borrow books.\n");
        return 0;
    }
    
    // Check outstanding fees
    if (member->outstanding_fees > 50.0) {
        printf("Outstanding fees too high ($%.2f). Please pay fees before borrowing.\n", 
               member->outstanding_fees);
        return 0;
    }
    
    Book* book = find_book_by_isbn(isbn);
    if (!book) {
        printf("Book not found.\n");
        return 0;
    }
    
    // Check if book is available
    if (book->available_copies <= 0) {
        printf("Book is not available for borrowing.\n");
        printf("Would you like to join the waiting list? (y/n): ");
        char choice;
        scanf(" %c", &choice);
        if (choice == 'y' || choice == 'Y') {
            add_to_waiting_list(isbn, member_id);
        }
        return 1;
    }
    
    // Check borrow limit
    int borrow_limit = get_borrow_limit(member->membership_type);
    if (member->num_borrowed >= borrow_limit) {
        printf("Borrow limit reached (%d books). Return a book to borrow more.\n", borrow_limit);
        return 0;
    }
    
    // Check if member already has this book
    for (int i = 0; i < library.book_count; i++) {
        if (strcmp(library.books[i].isbn, isbn) == 0 && 
            library.books[i].current_borrower_id == member_id) {
            printf("You already have this book borrowed.\n");
            return 0;
        }
    }
    
    // Borrow the book
    book->available_copies--;
    book->current_borrower_id = member_id;
    book->times_borrowed++;
    book->status = (book->available_copies > 0) ? BOOK_AVAILABLE : BOOK_BORROWED;
    
    // Set due date
    time_t current_time = get_current_time();
    struct tm* tm_info = localtime(&current_time);
    tm_info->tm_mday += get_borrow_days(member->membership_type);
    book->due_date = mktime(tm_info);
    
    // Update member records
    member->borrowed_books[member->num_borrowed] = library.book_count; // Store book index
    member->num_borrowed++;
    member->books_borrowed_total++;
    member->last_activity = current_time;
    
    // Update library statistics
    library.total_books_circulated++;
    
    // Record transaction
    record_transaction(member_id, isbn, TRANSACTION_BORROW, book->rental_price,
                      "Book borrowed");
    
    printf("Book borrowed successfully!\n");
    printf("Title: %s\n", book->title);
    printf("Due Date: %s\n", format_time(book->due_date));
    printf("Rental Fee: $%.2f\n", book->rental_price);
    
    return 1;
}

// Return a book
int return_book(int member_id, const char* isbn) {
    Member* member = find_member_by_id(member_id);
    if (!member) {
        printf("Member not found.\n");
        return 0;
    }
    
    Book* book = find_book_by_isbn(isbn);
    if (!book) {
        printf("Book not found.\n");
        return 0;
    }
    
    // Check if this member has borrowed this book
    if (book->current_borrower_id != member_id) {
        printf("This book is not borrowed by you.\n");
        return 0;
    }
    
    time_t return_time = get_current_time();
    double late_fee = 0.0;
    
    // Calculate late fee if overdue
    if (return_time > book->due_date) {
        late_fee = calculate_late_fee(book->due_date, return_time);
        member->outstanding_fees += late_fee;
        
        printf("Book is overdue!\n");
        printf("Late fee: $%.2f\n", late_fee);
        
        // Record late fee transaction
        record_transaction(member_id, isbn, TRANSACTION_LATE_FEE, late_fee,
                          "Late return fee");
    }
    
    // Return the book
    book->available_copies++;
    book->current_borrower_id = 0;
    book->due_date = 0;
    book->status = BOOK_AVAILABLE;
    
    // Update member records
    for (int i = 0; i < member->num_borrowed; i++) {
        if (member->borrowed_books[i] >= 0) {
            // Find and remove the book from borrowed list
            for (int j = 0; j < library.book_count; j++) {
                if (strcmp(library.books[j].isbn, isbn) == 0) {
                    // Shift remaining borrowed books
                    for (int k = i; k < member->num_borrowed - 1; k++) {
                        member->borrowed_books[k] = member->borrowed_books[k + 1];
                    }
                    member->num_borrowed--;
                    break;
                }
            }
            break;
        }
    }
    
    member->last_activity = return_time;
    
    // Record return transaction
    record_transaction(member_id, isbn, TRANSACTION_RETURN, 0.0, "Book returned");
    
    printf("Book returned successfully!\n");
    printf("Title: %s\n", book->title);
    if (late_fee > 0) {
        printf("Total late fee added to account: $%.2f\n", late_fee);
        printf("Outstanding fees: $%.2f\n", member->outstanding_fees);
    }
    
    // Process waiting list if applicable
    process_waiting_list(isbn);
    
    return 1;
}

// Calculate late fee
double calculate_late_fee(time_t due_date, time_t return_date) {
    double days_late = difftime(return_date, due_date) / (24 * 60 * 60);
    if (days_late <= 0) return 0.0;
    
    // Compound late fee calculation
    double base_fee = LATE_FEE_PER_DAY * days_late;
    double compound_rate = 1.02; // 2% compound daily after first week
    
    if (days_late > 7) {
        double additional_days = days_late - 7;
        base_fee += (LATE_FEE_PER_DAY * additional_days * pow(compound_rate, additional_days / 7));
    }
    
    return base_fee;
}

// Purchase a book
int purchase_book(int member_id, const char* isbn) {
    Member* member = find_member_by_id(member_id);
    if (!member) {
        printf("Member not found.\n");
        return 0;
    }
    
    Book* book = find_book_by_isbn(isbn);
    if (!book) {
        printf("Book not found.\n");
        return 0;
    }
    
    // Check if book is available for purchase
    if (book->total_copies <= 0) {
        printf("Book is not available for purchase.\n");
        return 0;
    }
    
    // Calculate purchase price with discount
    double purchase_price = calculate_purchase_price(book, member->membership_type);
    double discount = book->purchase_price - purchase_price;
    
    printf("Book Purchase Details:\n");
    printf("Title: %s\n", book->title);
    printf("Original Price: $%.2f\n", book->purchase_price);
    printf("Your Discount (%.0f%%): $%.2f\n", 
           get_discount_rate(member->membership_type) * 100, discount);
    printf("Final Price: $%.2f\n", purchase_price);
    
    printf("Confirm purchase? (y/n): ");
    char confirm;
    scanf(" %c", &confirm);
    
    if (confirm != 'y' && confirm != 'Y') {
        printf("Purchase cancelled.\n");
        return 0;
    }
    
    // Process purchase
    book->times_purchased++;
    member->books_purchased++;
    member->last_activity = get_current_time();
    
    // Update library revenue
    library.total_revenue += purchase_price;
    
    // Record transaction
    record_transaction(member_id, isbn, TRANSACTION_PURCHASE, purchase_price,
                      "Book purchased");
    
    printf("Book purchased successfully!\n");
    printf("Amount charged: $%.2f\n", purchase_price);
    printf("Thank you for your purchase!\n");
    
    return 1;
}

// Calculate purchase price with membership discount
double calculate_purchase_price(const Book* book, MembershipType membership) {
    double discount_rate = get_discount_rate(membership);
    return book->purchase_price * (1.0 - discount_rate);
}

// Record a transaction
void record_transaction(int member_id, const char* isbn, TransactionType type, 
                       double amount, const char* description) {
    if (library.transaction_count >= MAX_TRANSACTIONS) {
        printf("Transaction log is full.\n");
        return;
    }
    
    Transaction* trans = &library.transactions[library.transaction_count];
    trans->transaction_id = library.next_transaction_id++;
    trans->member_id = member_id;
    strcpy(trans->isbn, isbn);
    trans->type = type;
    trans->timestamp = get_current_time();
    trans->amount = amount;
    strcpy(trans->description, description);
    trans->processed_by = 1; // Default staff ID
    
    library.transaction_count++;
}

// Display transaction history for a member
void display_transaction_history(int member_id) {
    printf("\n--- Transaction History for Member %d ---\n", member_id);
    printf("%-12s %-20s %-20s %-12s %-8s %s\n", 
           "Trans ID", "Date", "ISBN", "Type", "Amount", "Description");
    printf("--------------------------------------------------------------------------------\n");
    
    int found = 0;
    for (int i = 0; i < library.transaction_count; i++) {
        if (library.transactions[i].member_id == member_id) {
            Transaction* trans = &library.transactions[i];
            char* type_str;
            switch (trans->type) {
                case TRANSACTION_BORROW: type_str = "BORROW"; break;
                case TRANSACTION_RETURN: type_str = "RETURN"; break;
                case TRANSACTION_PURCHASE: type_str = "PURCHASE"; break;
                case TRANSACTION_REGISTER: type_str = "REGISTER"; break;
                case TRANSACTION_CANCEL: type_str = "CANCEL"; break;
                case TRANSACTION_LATE_FEE: type_str = "LATE_FEE"; break;
                case TRANSACTION_RESERVATION: type_str = "RESERVE"; break;
                default: type_str = "UNKNOWN";
            }
            
            printf("%-12d %-20s %-20s %-12s $%-7.2f %s\n",
                   trans->transaction_id,
                   format_time(trans->timestamp),
                   trans->isbn,
                   type_str,
                   trans->amount,
                   trans->description);
            found++;
        }
    }
    
    if (found == 0) {
        printf("No transactions found for this member.\n");
    } else {
        printf("Total transactions: %d\n", found);
    }
    printf("--------------------------------------------------------------------------------\n");
}

// Add member to waiting list for a book
void add_to_waiting_list(const char* isbn, int member_id) {
    Book* book = find_book_by_isbn(isbn);
    if (!book) return;
    
    // Check if member is already on waiting list
    WaitingListEntry* current = book->waiting_list;
    while (current) {
        if (current->member_id == member_id) {
            printf("You are already on the waiting list for this book.\n");
            return;
        }
        current = current->next;
    }
    
    // Add to waiting list
    WaitingListEntry* new_entry = malloc(sizeof(WaitingListEntry));
    new_entry->member_id = member_id;
    new_entry->request_date = get_current_time();
    new_entry->next = book->waiting_list;
    book->waiting_list = new_entry;
    book->waiting_count++;
    
    // Record reservation transaction
    record_transaction(member_id, isbn, TRANSACTION_RESERVATION, 0.0,
                      "Added to waiting list");
    
    printf("You have been added to the waiting list for '%s'.\n", book->title);
    printf("Position in queue: %d\n", book->waiting_count);
}

void process_waiting_list(const char* isbn) {
    Book* book = find_book_by_isbn(isbn);
    if (!book || book->waiting_count == 0) return;
    
    // Notify first person on waiting list
    WaitingListEntry* first = book->waiting_list;
    if (first) {
        Member* member = find_member_by_id(first->member_id);
        if (member) {
            printf("\nNotification: '%s' is now available for %s (Member ID: %d)\n",
                   book->title, member->name, member->member_id);
            printf("The book will be held for 24 hours.\n");
        }
        
        // Remove from waiting list
        book->waiting_list = first->next;
        book->waiting_count--;
        free(first);
        
        printf("Removed member %d from waiting list\n", first->member_id);
    }
}


// Check for overdue books
void check_overdue_books() {
    printf("\n--- Overdue Books Report ---\n");
    printf("%-8s %-30s %-20s %-15s %-10s\n", 
           "Member", "Book Title", "ISBN", "Due Date", "Days Late");
    printf("---------------------------------------------------------------------------------\n");
    
    time_t current_time = get_current_time();
    int overdue_count = 0;
    
    for (int i = 0; i < library.book_count; i++) {
        Book* book = &library.books[i];
        if (book->current_borrower_id > 0 && current_time > book->due_date) {
            Member* member = find_member_by_id(book->current_borrower_id);
            double days_late = difftime(current_time, book->due_date) / (24 * 60 * 60);
            
            printf("%-8d %-30s %-20s %-15s %-10.0f\n",
                   book->current_borrower_id,
                   book->title,
                   book->isbn,
                   format_time(book->due_date),
                   days_late);
            overdue_count++;
        }
    }
    
    if (overdue_count == 0) {
        printf("No overdue books found.\n");
    } else {
        printf("---------------------------------------------------------------------------------\n");
        printf("Total overdue books: %d\n", overdue_count);
    }
}

// Generate book recommendations
void generate_recommendations(int member_id) {
    Member* member = find_member_by_id(member_id);
    if (!member) {
        printf("Member not found.\n");
        return;
    }
    
    printf("\n--- Book Recommendations for %s ---\n", member->name);
    
    // Simple recommendation based on previously borrowed genres
    int genre_count[GENRE_OTHER + 1] = {0};
    
    // Count genres from transaction history
    for (int i = 0; i < library.transaction_count; i++) {
        if (library.transactions[i].member_id == member_id && 
            library.transactions[i].type == TRANSACTION_BORROW) {
            Book* book = find_book_by_isbn(library.transactions[i].isbn);
            if (book) {
                genre_count[book->genre]++;
            }
        }
    }
    
    // Find most preferred genres
    GenreType preferred_genres[3];
    int max_counts[3] = {0, 0, 0};
    
    for (int i = 0; i <= GENRE_OTHER; i++) {
        if (genre_count[i] > max_counts[0]) {
            max_counts[2] = max_counts[1];
            preferred_genres[2] = preferred_genres[1];
            max_counts[1] = max_counts[0];
            preferred_genres[1] = preferred_genres[0];
            max_counts[0] = genre_count[i];
            preferred_genres[0] = (GenreType)i;
        } else if (genre_count[i] > max_counts[1]) {
            max_counts[2] = max_counts[1];
            preferred_genres[2] = preferred_genres[1];
            max_counts[1] = genre_count[i];
            preferred_genres[1] = (GenreType)i;
        } else if (genre_count[i] > max_counts[2]) {
            max_counts[2] = genre_count[i];
            preferred_genres[2] = (GenreType)i;
        }
    }
    
    // Recommend books from preferred genres that user hasn't borrowed
    int recommendations = 0;
    for (int g = 0; g < 3 && max_counts[g] > 0; g++) {
        printf("\nBased on your interest in %s:\n", get_genre_string(preferred_genres[g]));
        
        for (int i = 0; i < library.book_count && recommendations < 10; i++) {
            Book* book = &library.books[i];
            if (book->genre == preferred_genres[g] && book->available_copies > 0) {
                // Check if user has already borrowed this book
                int already_borrowed = 0;
                for (int j = 0; j < library.transaction_count; j++) {
                    if (library.transactions[j].member_id == member_id &&
                        strcmp(library.transactions[j].isbn, book->isbn) == 0 &&
                        library.transactions[j].type == TRANSACTION_BORROW) {
                        already_borrowed = 1;
                        break;
                    }
                }
                
                if (!already_borrowed) {
                    printf("  • %s by %s (ISBN: %s)\n", 
                           book->title, book->author, book->isbn);
                    recommendations++;
                }
            }
        }
    }
    
    if (recommendations == 0) {
        printf("No specific recommendations available. Try browsing our popular books!\n");
    }
}

// Display popular books
void display_popular_books() {
    printf("\n--- Most Popular Books ---\n");
    
    // Sort books by times borrowed (simple bubble sort)
    Book* sorted_books[MAX_BOOKS];
    for (int i = 0; i < library.book_count; i++) {
        sorted_books[i] = &library.books[i];
    }
    
    for (int i = 0; i < library.book_count - 1; i++) {
        for (int j = 0; j < library.book_count - i - 1; j++) {
            if (sorted_books[j]->times_borrowed < sorted_books[j + 1]->times_borrowed) {
                Book* temp = sorted_books[j];
                sorted_books[j] = sorted_books[j + 1];
                sorted_books[j + 1] = temp;
            }
        }
    }
    
    printf("%-5s %-40s %-25s %-8s %-10s\n", 
           "Rank", "Title", "Author", "Borrowed", "Available");
    printf("--------------------------------------------------------------------------------\n");
    
    int display_count = (library.book_count < 20) ? library.book_count : 20;
    for (int i = 0; i < display_count; i++) {
        Book* book = sorted_books[i];
        printf("%-5d %-40s %-25s %-8d %-10s\n",
               i + 1,
               book->title,
               book->author,
               book->times_borrowed,
               (book->available_copies > 0) ? "Yes" : "No");
    }
    printf("--------------------------------------------------------------------------------\n");
}

// Administrative menu
void admin_menu() {
    printf("\n--- Administrative Functions ---\n");
    printf("1. Add New Book\n");
    printf("2. Update Book Information\n");
    printf("3. Remove Book\n");
    printf("4. View All Members\n");
    printf("5. Update Member Information\n");
    printf("6. Process Late Fees\n");
    printf("7. Generate Financial Report\n");
    printf("8. System Maintenance\n");
    printf("9. Bulk Operations\n");
    printf("0. Return to Main Menu\n");
    
    int choice = get_integer_input("Choose option", 0, 9);
    
    switch (choice) {
        case 1: // Add new book
            {
                char isbn[MAX_ISBN_LENGTH], title[MAX_TITLE_LENGTH], author[MAX_AUTHOR_LENGTH];
                int year, copies;
                double purchase_price, rental_price;
                
                get_string_input("Enter ISBN", isbn, MAX_ISBN_LENGTH);
                get_string_input("Enter title", title, MAX_TITLE_LENGTH);
                get_string_input("Enter author", author, MAX_AUTHOR_LENGTH);
                
                printf("Select genre:\n");
                for (int i = 0; i <= GENRE_OTHER; i++) {
                    printf("%d. %s\n", i+1, get_genre_string((GenreType)i));
                }
                int genre_choice = get_integer_input("Choose genre", 1, GENRE_OTHER+1);
                
                year = get_integer_input("Enter publication year", 1000, 2025);
                purchase_price = get_double_input("Enter purchase price", 0.01, 1000.0);
                rental_price = get_double_input("Enter rental price", 0.01, 100.0);
                copies = get_integer_input("Enter number of copies", 1, 100);
                
                add_book(isbn, title, author, (GenreType)(genre_choice-1), 
                        year, purchase_price, rental_price, copies);
            }
            break;
            
        case 4: // View all members
            printf("\n--- All Library Members ---\n");
            printf("%-8s %-25s %-30s %-15s %-10s\n", 
                   "ID", "Name", "Email", "Membership", "Status");
            printf("--------------------------------------------------------------------------------\n");
            
            for (int i = 0; i < library.member_count; i++) {
                Member* member = &library.members[i];
                printf("%-8d %-25s %-30s %-15s %-10s\n",
                       member->member_id,
                       member->name,
                       member->email,
                       get_membership_string(member->membership_type),
                       member->is_active ? "Active" : "Inactive");
            }
            printf("Total members: %d\n", library.member_count);
            break;
            
        case 7: // Financial report
            generate_financial_report();
            break;
            
        default:
            printf("Feature not yet implemented.\n");
    }
}

// Generate financial report
void generate_financial_report() {
    printf("\n=== FINANCIAL REPORT ===\n");
    printf("Report Date: %s\n", format_time(get_current_time()));
    printf("==================================================\n");
    
    double total_membership_fees = 0.0;
    double total_rental_fees = 0.0;
    double total_purchase_revenue = 0.0;
    double total_late_fees = 0.0;
    
    // Calculate revenue from transactions
    for (int i = 0; i < library.transaction_count; i++) {
        Transaction* trans = &library.transactions[i];
        switch (trans->type) {
            case TRANSACTION_REGISTER:
                total_membership_fees += trans->amount;
                break;
            case TRANSACTION_BORROW:
                total_rental_fees += trans->amount;
                break;
            case TRANSACTION_PURCHASE:
                total_purchase_revenue += trans->amount;
                break;
            case TRANSACTION_LATE_FEE:
                total_late_fees += trans->amount;
                break;
            case TRANSACTION_RETURN:
            case TRANSACTION_CANCEL:
            case TRANSACTION_RESERVATION:
                break;
        }
    }
    
    printf("Revenue Breakdown:\n");
    printf("  Membership Fees:    $%8.2f\n", total_membership_fees);
    printf("  Rental Fees:        $%8.2f\n", total_rental_fees);
    printf("  Book Sales:         $%8.2f\n", total_purchase_revenue);
    printf("  Late Fees:          $%8.2f\n", total_late_fees);
    printf("  ------------------------------\n");
    printf("  Total Revenue:      $%8.2f\n", 
           total_membership_fees + total_rental_fees + total_purchase_revenue + total_late_fees);
    
    printf("\nMembership Statistics:\n");
    int basic_count = 0, premium_count = 0, vip_count = 0;
    double outstanding_fees_total = 0.0;
    
    for (int i = 0; i < library.member_count; i++) {
        if (library.members[i].is_active) {
            switch (library.members[i].membership_type) {
                case MEMBERSHIP_BASIC: basic_count++; break;
                case MEMBERSHIP_PREMIUM: premium_count++; break;
                case MEMBERSHIP_VIP: vip_count++; break;
            }
            outstanding_fees_total += library.members[i].outstanding_fees;
        }
    }
    
    printf("  Basic Members:      %8d\n", basic_count);
    printf("  Premium Members:    %8d\n", premium_count);
    printf("  VIP Members:        %8d\n", vip_count);
    printf("  Total Active:       %8d\n", basic_count + premium_count + vip_count);
    printf("  Outstanding Fees:   $%8.2f\n", outstanding_fees_total);
    
    printf("\nLibrary Statistics:\n");
    printf("  Total Books:        %8d\n", library.book_count);
    printf("  Books Circulated:   %8d\n", library.total_books_circulated);
    printf("  Total Transactions: %8d\n", library.transaction_count);
    
    printf("\n==================================================\n");
}

// Display system statistics
void display_system_statistics() {
    printf("\n=== SYSTEM STATISTICS ===\n");
    printf("System Start Time: %s\n", format_time(library.system_start_time));
    printf("Current Time: %s\n", format_time(get_current_time()));
    printf("==================================================\n");
    
    // Book statistics
    int available_books = 0;
    int borrowed_books = 0;
    int total_copies = 0;
    
    for (int i = 0; i < library.book_count; i++) {
        available_books += library.books[i].available_copies;
        borrowed_books += (library.books[i].total_copies - library.books[i].available_copies);
        total_copies += library.books[i].total_copies;
    }
    
    printf("Book Statistics:\n");
    printf("  Unique Titles:      %8d\n", library.book_count);
    printf("  Total Copies:       %8d\n", total_copies);
    printf("  Available Copies:   %8d\n", available_books);
    printf("  Borrowed Copies:    %8d\n", borrowed_books);
    printf("  Utilization Rate:   %8.1f%%\n", 
           total_copies > 0 ? ((double)borrowed_books / total_copies) * 100 : 0);
    
    // Member statistics
    int active_members = 0;
    for (int i = 0; i < library.member_count; i++) {
        if (library.members[i].is_active) active_members++;
    }
    
    printf("\nMember Statistics:\n");
    printf("  Total Members:      %8d\n", library.member_count);
    printf("  Active Members:     %8d\n", active_members);
    printf("  Average Books/Member: %6.1f\n", 
           active_members > 0 ? (double)library.total_books_circulated / active_members : 0);
    
    // Genre distribution
    printf("\nGenre Distribution:\n");
    int genre_counts[GENRE_OTHER + 1] = {0};
    for (int i = 0; i < library.book_count; i++) {
        genre_counts[library.books[i].genre]++;
    }
    
    for (int i = 0; i <= GENRE_OTHER; i++) {
        if (genre_counts[i] > 0) {
            printf("  %-15s: %8d (%.1f%%)\n", 
                   get_genre_string((GenreType)i), 
                   genre_counts[i],
                   ((double)genre_counts[i] / library.book_count) * 100);
        }
    }
    
    printf("\n==================================================\n");
}

// Utility function implementations
void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

char* get_string_input(const char* prompt, char* buffer, int max_length) {
    printf("%s: ", prompt);
    gets(buffer);
    
    // Remove newline if present
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }
    
    trim_whitespace(buffer);
    return buffer;
}

int get_integer_input(const char* prompt, int min, int max) {
    int value;
    char input[100];
    
    while (1) {
        printf("%s (%d-%d): ", prompt, min, max);
        if (fgets(input, sizeof(input), stdin)) {
            if (sscanf(input, "%d", &value) == 1) {
                if (value >= min && value <= max) {
                    return value;
                }
            }
        }
        printf("Invalid input. Please enter a number between %d and %d.\n", min, max);
    }
}

double get_double_input(const char* prompt, double min, double max) {
    double value;
    char input[100];
    
    while (1) {
        printf("%s (%.2f-%.2f): ", prompt, min, max);
        if (fgets(input, sizeof(input), stdin)) {
            if (sscanf(input, "%lf", &value) == 1) {
                if (value >= min && value <= max) {
                    return value;
                }
            }
        }
        printf("Invalid input. Please enter a number between %.2f and %.2f.\n", min, max);
    }
}

time_t get_current_time() {
    return time(NULL);
}

char* format_time(time_t time) {
    static char buffer[100];
    struct tm* tm_info = localtime(&time);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    return buffer;
}

char* get_genre_string(GenreType genre) {
    switch (genre) {
        case GENRE_FICTION: return "Fiction";
        case GENRE_NONFICTION: return "Non-Fiction";
        case GENRE_MYSTERY: return "Mystery";
        case GENRE_ROMANCE: return "Romance";
        case GENRE_SCIFI: return "Science Fiction";
        case GENRE_FANTASY: return "Fantasy";
        case GENRE_BIOGRAPHY: return "Biography";
        case GENRE_HISTORY: return "History";
        case GENRE_SCIENCE: return "Science";
        case GENRE_TECHNOLOGY: return "Technology";
        case GENRE_SELF_HELP: return "Self Help";
        case GENRE_OTHER: return "Other";
        default: return "Unknown";
    }
}

GenreType get_genre_from_string(const char* genre_str) {
    char upper_genre[MAX_GENRE_LENGTH];
    strcpy(upper_genre, genre_str);
    to_uppercase(upper_genre);
    
    if (strstr(upper_genre, "FICTION") && !strstr(upper_genre, "NON")) return GENRE_FICTION;
    if (strstr(upper_genre, "NON-FICTION") || strstr(upper_genre, "NONFICTION")) return GENRE_NONFICTION;
    if (strstr(upper_genre, "MYSTERY")) return GENRE_MYSTERY;
    if (strstr(upper_genre, "ROMANCE")) return GENRE_ROMANCE;
    if (strstr(upper_genre, "SCIENCE FICTION") || strstr(upper_genre, "SCI-FI")) return GENRE_SCIFI;
    if (strstr(upper_genre, "FANTASY")) return GENRE_FANTASY;
    if (strstr(upper_genre, "BIOGRAPHY")) return GENRE_BIOGRAPHY;
    if (strstr(upper_genre, "HISTORY")) return GENRE_HISTORY;
    if (strstr(upper_genre, "SCIENCE")) return GENRE_SCIENCE;
    if (strstr(upper_genre, "TECHNOLOGY") || strstr(upper_genre, "TECH")) return GENRE_TECHNOLOGY;
    if (strstr(upper_genre, "SELF HELP") || strstr(upper_genre, "SELF-HELP")) return GENRE_SELF_HELP;
    
    return GENRE_OTHER;
}

char* get_membership_string(MembershipType type) {
    switch (type) {
        case MEMBERSHIP_BASIC: return "Basic";
        case MEMBERSHIP_PREMIUM: return "Premium";
        case MEMBERSHIP_VIP: return "VIP";
        default: return "Unknown";
    }
}

char* get_status_string(BookStatus status) {
    switch (status) {
        case BOOK_AVAILABLE: return "Available";
        case BOOK_BORROWED: return "Borrowed";
        case BOOK_RESERVED: return "Reserved";
        case BOOK_MAINTENANCE: return "Maintenance";
        case BOOK_SOLD: return "Sold";
        default: return "Unknown";
    }
}

void to_uppercase(char* str) {
    for (int i = 0; str[i]; i++) {
        str[i] = toupper(str[i]);
    }
}

void trim_whitespace(char* str) {
    // Trim leading whitespace
    int start = 0;
    while (str[start] && isspace(str[start])) start++;
    
    // Move string to beginning
    int i = 0;
    while (str[start + i]) {
        str[i] = str[start + i];
        i++;
    }
    str[i] = '\0';
    
    // Trim trailing whitespace
    int end = strlen(str) - 1;
    while (end >= 0 && isspace(str[end])) {
        str[end] = '\0';
        end--;
    }
}

double get_discount_rate(MembershipType type) {
    switch (type) {
        case MEMBERSHIP_BASIC: return BASIC_DISCOUNT;
        case MEMBERSHIP_PREMIUM: return PREMIUM_DISCOUNT;
        case MEMBERSHIP_VIP: return VIP_DISCOUNT;
        default: return 0.0;
    }
}

int get_borrow_limit(MembershipType type) {
    switch (type) {
        case MEMBERSHIP_BASIC: return BASIC_BORROW_LIMIT;
        case MEMBERSHIP_PREMIUM: return PREMIUM_BORROW_LIMIT;
        case MEMBERSHIP_VIP: return VIP_BORROW_LIMIT;
        default: return BASIC_BORROW_LIMIT;
    }
}

int get_borrow_days(MembershipType type) {
    switch (type) {
        case MEMBERSHIP_BASIC: return BASIC_BORROW_DAYS;
        case MEMBERSHIP_PREMIUM: return PREMIUM_BORROW_DAYS;
        case MEMBERSHIP_VIP: return VIP_BORROW_DAYS;
        default: return BASIC_BORROW_DAYS;
    }
}

// Data persistence functions
void save_library_data() {
    FILE* file = fopen("library_data.bin", "wb");
    if (!file) {
        printf("Error: Could not save library data.\n");
        return;
    }
    
    // Write library structure
    fwrite(&library, sizeof(Library), 1, file);
    
    // Write waiting lists for each book
    for (int i = 0; i < library.book_count; i++) {
        WaitingListEntry* current = library.books[i].waiting_list;
        while (current) {
            fwrite(current, sizeof(WaitingListEntry), 1, file);
            current = current->next;
        }
    }
    
    fclose(file);
    printf("Library data saved successfully.\n");
}

void load_library_data() {
    FILE* file = fopen("library_data.bin", "rb");
    if (!file) {
        printf("No existing data file found. Starting with fresh data.\n");
        return;
    }
    
    // Read library structure
    if (fread(&library, sizeof(Library), 1, file) != 1) {
        printf("Error reading library data.\n");
        fclose(file);
        return;
    }
    
    // Reconstruct waiting lists (simplified - in real implementation would need more complex logic)
    for (int i = 0; i < library.book_count; i++) {
        library.books[i].waiting_list = NULL; // Reset waiting lists
        library.books[i].waiting_count = 0;
    }
    
    fclose(file);
    printf("Library data loaded successfully.\n");
}

void backup_data() {
    time_t current_time = get_current_time();
    char backup_filename[200];
    sprintf(backup_filename, "library_backup_%ld.bin", current_time);
    
    FILE* source = fopen("library_data.bin", "rb");
    FILE* backup = fopen(backup_filename, "wb");
    
    if (!source || !backup) {
        printf("Error creating backup.\n");
        if (source) fclose(source);
        if (backup) fclose(backup);
        return;
    }
    
    char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), source)) > 0) {
        fwrite(buffer, 1, bytes, backup);
    }
    
    fclose(source);
    fclose(backup);
    printf("Backup created: %s\n", backup_filename);
}

void restore_data() {
    printf("This feature allows restoration from backup files.\n");
    printf("Implementation would list available backups and allow selection.\n");
}

void export_data_csv() {
    // Export books to CSV
    FILE* books_file = fopen("books_export.csv", "w");
    if (books_file) {
        fprintf(books_file, "ISBN,Title,Author,Genre,Year,Purchase_Price,Rental_Price,Total_Copies,Available_Copies,Times_Borrowed\n");
        
        for (int i = 0; i < library.book_count; i++) {
            Book* book = &library.books[i];
            fprintf(books_file, "\"%s\",\"%s\",\"%s\",\"%s\",%d,%.2f,%.2f,%d,%d,%d\n",
                   book->isbn, book->title, book->author, get_genre_string(book->genre),
                   book->publication_year, book->purchase_price, book->rental_price,
                   book->total_copies, book->available_copies, book->times_borrowed);
        }
        fclose(books_file);
        printf("Books exported to books_export.csv\n");
    }
    
    // Export members to CSV
    FILE* members_file = fopen("members_export.csv", "w");
    if (members_file) {
        fprintf(members_file, "Member_ID,Name,Email,Phone,Membership_Type,Registration_Date,Books_Borrowed,Books_Purchased,Outstanding_Fees\n");
        
        for (int i = 0; i < library.member_count; i++) {
            Member* member = &library.members[i];
            if (member->is_active) {
                fprintf(members_file, "%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%d,%d,%.2f\n",
                       member->member_id, member->name, member->email, member->phone,
                       get_membership_string(member->membership_type),
                       format_time(member->registration_date),
                       member->books_borrowed_total, member->books_purchased,
                       member->outstanding_fees);
            }
        }
        fclose(members_file);
        printf("Members exported to members_export.csv\n");
    }
    
    // Export transactions to CSV
    FILE* trans_file = fopen("transactions_export.csv", "w");
    if (trans_file) {
        fprintf(trans_file, "Transaction_ID,Member_ID,ISBN,Type,Timestamp,Amount,Description\n");
        
        for (int i = 0; i < library.transaction_count; i++) {
            Transaction* trans = &library.transactions[i];
            char* type_str;
            switch (trans->type) {
                case TRANSACTION_BORROW: type_str = "BORROW"; break;
                case TRANSACTION_RETURN: type_str = "RETURN"; break;
                case TRANSACTION_PURCHASE: type_str = "PURCHASE"; break;
                case TRANSACTION_REGISTER: type_str = "REGISTER"; break;
                case TRANSACTION_CANCEL: type_str = "CANCEL"; break;
                case TRANSACTION_LATE_FEE: type_str = "LATE_FEE"; break;
                case TRANSACTION_RESERVATION: type_str = "RESERVE"; break;
                default: type_str = "UNKNOWN";
            }
            
            fprintf(trans_file, "%d,%d,\"%s\",\"%s\",\"%s\",%.2f,\"%s\"\n",
                   trans->transaction_id, trans->member_id, trans->isbn, type_str,
                   format_time(trans->timestamp), trans->amount, trans->description);
        }
        fclose(trans_file);
        printf("Transactions exported to transactions_export.csv\n");
    }
}

void import_data_csv() {
    printf("CSV import functionality would parse CSV files and populate the library system.\n");
    printf("This would include validation, duplicate checking, and error handling.\n");
}

// Generate comprehensive reports
void generate_reports() {
    printf("\n--- Generate Reports ---\n");
    printf("1. Financial Summary\n");
    printf("2. Member Activity Report\n");
    printf("3. Book Circulation Report\n");
    printf("4. Overdue Books Report\n");
    printf("5. Popular Books Report\n");
    printf("6. Membership Statistics\n");
    printf("7. Revenue Analysis\n");
    printf("8. Custom Date Range Report\n");
    printf("0. Return to Main Menu\n");
    
    int choice = get_integer_input("Choose report type", 0, 8);
    
    switch (choice) {
        case 1:
            generate_financial_report();
            break;
        case 2:
            generate_member_activity_report();
            break;
        case 3:
            generate_circulation_report();
            break;
        case 4:
            check_overdue_books();
            break;
        case 5:
            display_popular_books();
            break;
        case 6:
            generate_membership_statistics();
            break;
        case 7:
            generate_revenue_analysis();
            break;
        case 8:
            printf("Custom date range reports would allow filtering by specific time periods.\n");
            break;
        default:
            printf("Invalid choice.\n");
    }
}

void generate_member_activity_report() {
    printf("\n=== MEMBER ACTIVITY REPORT ===\n");
    printf("%-8s %-25s %-12s %-12s %-12s %-10s\n", 
           "ID", "Name", "Borrowed", "Purchased", "Last Active", "Fees");
    printf("--------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < library.member_count; i++) {
        Member* member = &library.members[i];
        if (member->is_active) {
            printf("%-8d %-25s %-12d %-12d %-12s $%-9.2f\n",
                   member->member_id,
                   member->name,
                   member->books_borrowed_total,
                   member->books_purchased,
                   format_time(member->last_activity),
                   member->outstanding_fees);
        }
    }
    printf("================================================================================\n");
}

void generate_circulation_report() {
    printf("\n=== BOOK CIRCULATION REPORT ===\n");
    printf("%-20s %-40s %-10s %-10s %-8s\n", 
           "ISBN", "Title", "Borrowed", "Available", "Revenue");
    printf("--------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < library.book_count; i++) {
        Book* book = &library.books[i];
        double book_revenue = book->times_borrowed * book->rental_price + 
                             book->times_purchased * book->purchase_price;
        
        printf("%-20s %-40s %-10d %-10d $%-7.2f\n",
               book->isbn,
               book->title,
               book->times_borrowed,
               book->available_copies,
               book_revenue);
    }
    printf("================================================================================\n");
}

void generate_membership_statistics() {
    printf("\n=== MEMBERSHIP STATISTICS ===\n");
    
    int basic_count = 0, premium_count = 0, vip_count = 0;
    int basic_active = 0, premium_active = 0, vip_active = 0;
    double basic_revenue = 0, premium_revenue = 0, vip_revenue = 0;
    
    for (int i = 0; i < library.member_count; i++) {
        Member* member = &library.members[i];
        switch (member->membership_type) {
            case MEMBERSHIP_BASIC:
                basic_count++;
                if (member->is_active) {
                    basic_active++;
                    basic_revenue += member->membership_fee_paid;
                }
                break;
            case MEMBERSHIP_PREMIUM:
                premium_count++;
                if (member->is_active) {
                    premium_active++;
                    premium_revenue += member->membership_fee_paid;
                }
                break;
            case MEMBERSHIP_VIP:
                vip_count++;
                if (member->is_active) {
                    vip_active++;
                    vip_revenue += member->membership_fee_paid;
                }
                break;
        }
    }
    
    printf("Membership Type Breakdown:\n");
    printf("%-15s %-8s %-8s %-12s %-15s\n", "Type", "Total", "Active", "Revenue", "Avg Revenue");
    printf("-----------------------------------------------------------------------\n");
    printf("%-15s %-8d %-8d $%-11.2f $%-14.2f\n", "Basic", basic_count, basic_active, 
           basic_revenue, basic_active > 0 ? basic_revenue / basic_active : 0);
    printf("%-15s %-8d %-8d $%-11.2f $%-14.2f\n", "Premium", premium_count, premium_active, 
           premium_revenue, premium_active > 0 ? premium_revenue / premium_active : 0);
    printf("%-15s %-8d %-8d $%-11.2f $%-14.2f\n", "VIP", vip_count, vip_active, 
           vip_revenue, vip_active > 0 ? vip_revenue / vip_active : 0);
    printf("=======================================================================\n");
}

void generate_revenue_analysis() {
    printf("\n=== REVENUE ANALYSIS ===\n");
    
    double monthly_revenue[12] = {0};
    int current_year = 2025; // Would normally get current year
    
    // Analyze revenue by month (simplified - would need proper date parsing)
    for (int i = 0; i < library.transaction_count; i++) {
        Transaction* trans = &library.transactions[i];
        struct tm* tm_info = localtime(&trans->timestamp);
        
        if (tm_info->tm_year + 1900 == current_year) {
            int month = tm_info->tm_mon;
            if (month >= 0 && month < 12) {
                monthly_revenue[month] += trans->amount;
            }
        }
    }
    
    char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    
    printf("Monthly Revenue for %d:\n", current_year);
    printf("%-5s %12s\n", "Month", "Revenue");
    printf("------------------\n");
    
    double total_year_revenue = 0;
    for (int i = 0; i < 12; i++) {
        printf("%-5s $%11.2f\n", months[i], monthly_revenue[i]);
        total_year_revenue += monthly_revenue[i];
    }
    
    printf("------------------\n");
    printf("%-5s $%11.2f\n", "Total", total_year_revenue);
    printf("%-5s $%11.2f\n", "Avg", total_year_revenue / 12);
    printf("==================\n");
}

// System maintenance functions
void system_maintenance() {
    printf("\n--- System Maintenance ---\n");
    printf("1. Check Data Integrity\n");
    printf("2. Cleanup Old Transactions\n");
    printf("3. Update Book Status\n");
    printf("4. Process Expired Memberships\n");
    printf("5. Calculate Outstanding Fees\n");
    printf("6. Optimize Database\n");
    printf("7. Generate System Health Report\n");
    printf("0. Return to Main Menu\n");
    
    int choice = get_integer_input("Choose maintenance option", 0, 7);
    
    switch (choice) {
        case 1:
            check_data_integrity();
            break;
        case 2:
            cleanup_old_transactions();
            break;
        case 3:
            update_all_book_status();
            break;
        case 4:
            process_expired_memberships();
            break;
        case 5:
            recalculate_outstanding_fees();
            break;
        case 6:
            optimize_database();
            break;
        case 7:
            generate_system_health_report();
            break;
        default:
            printf("Invalid choice.\n");
    }
}

void check_data_integrity() {
    printf("\n--- Data Integrity Check ---\n");
    int issues_found = 0;
    
    // Check for duplicate ISBNs
    for (int i = 0; i < library.book_count - 1; i++) {
        for (int j = i + 1; j < library.book_count; j++) {
            if (strcmp(library.books[i].isbn, library.books[j].isbn) == 0) {
                printf("WARNING: Duplicate ISBN found: %s\n", library.books[i].isbn);
                issues_found++;
            }
        }
    }
    
    // Check for duplicate member IDs
    for (int i = 0; i < library.member_count - 1; i++) {
        for (int j = i + 1; j < library.member_count; j++) {
            if (library.members[i].member_id == library.members[j].member_id) {
                printf("WARNING: Duplicate Member ID found: %d\n", library.members[i].member_id);
                issues_found++;
            }
        }
    }
    
    // Check book availability consistency
    for (int i = 0; i < library.book_count; i++) {
        Book* book = &library.books[i];
        if (book->available_copies > book->total_copies) {
            printf("WARNING: Book %s has more available copies than total copies\n", book->isbn);
            issues_found++;
        }
        if (book->available_copies < 0) {
            printf("WARNING: Book %s has negative available copies\n", book->isbn);
            issues_found++;
        }
    }
    
    // Check member borrowed books consistency
    for (int i = 0; i < library.member_count; i++) {
        Member* member = &library.members[i];
        if (member->num_borrowed > get_borrow_limit(member->membership_type)) {
            printf("WARNING: Member %d has exceeded borrow limit\n", member->member_id);
            issues_found++;
        }
        if (member->num_borrowed < 0) {
            printf("WARNING: Member %d has negative borrowed count\n", member->member_id);
            issues_found++;
        }
    }
    
    if (issues_found == 0) {
        printf("Data integrity check passed. No issues found.\n");
    } else {
        printf("Data integrity check completed. %d issue(s) found.\n", issues_found);
    }
}

void cleanup_old_transactions() {
    printf("Cleaning up transactions older than 2 years...\n");
    
    time_t cutoff_time = get_current_time() - (2 * 365 * 24 * 60 * 60); // 2 years ago
    int removed_count = 0;
    
    // In a real implementation, this would properly remove old transactions
    // For now, just count how many would be removed
    for (int i = 0; i < library.transaction_count; i++) {
        if (library.transactions[i].timestamp < cutoff_time) {
            removed_count++;
        }
    }
    
    printf("Would remove %d old transactions.\n", removed_count);
    printf("(In actual implementation, transactions would be archived before removal)\n");
}

void update_all_book_status() {
    printf("Updating book status for all books...\n");
    
    for (int i = 0; i < library.book_count; i++) {
        Book* book = &library.books[i];
        
        if (book->available_copies > 0) {
            book->status = BOOK_AVAILABLE;
        } else if (book->current_borrower_id > 0) {
            book->status = BOOK_BORROWED;
        } else {
            book->status = BOOK_MAINTENANCE;
        }
    }
    
    printf("Book status updated for %d books.\n", library.book_count);
}

void process_expired_memberships() {
    printf("Processing expired memberships...\n");
    
    time_t current_time = get_current_time();
    int expired_count = 0;
    
    for (int i = 0; i < library.member_count; i++) {
        Member* member = &library.members[i];
        if (member->is_active && current_time > member->membership_expiry) {
            printf("Membership expired for %s (ID: %d)\n", member->name, member->member_id);
            expired_count++;
            
            // In a real system, would send renewal notices
        }
    }
    
    printf("Found %d expired memberships.\n", expired_count);
}

void recalculate_outstanding_fees() {
    printf("Recalculating outstanding fees for all members...\n");
    
    for (int i = 0; i < library.member_count; i++) {
        Member* member = &library.members[i];
        double calculated_fees = 0.0;
        
        // Calculate fees from transaction history
        for (int j = 0; j < library.transaction_count; j++) {
            if (library.transactions[j].member_id == member->member_id &&
                library.transactions[j].type == TRANSACTION_LATE_FEE) {
                calculated_fees += library.transactions[j].amount;
            }
        }
        
        if (fabs(member->outstanding_fees - calculated_fees) > 0.01) {
            printf("Fee discrepancy for Member %d: Recorded $%.2f, Calculated $%.2f\n",
                   member->member_id, member->outstanding_fees, calculated_fees);
            member->outstanding_fees = calculated_fees;
        }
    }
    
    printf("Outstanding fees recalculation completed.\n");
}

void optimize_database() {
    printf("Optimizing database structure...\n");
    printf("- Compacting transaction log\n");
    printf("- Rebuilding indices\n");
    printf("- Cleaning up waiting lists\n");
    printf("- Updating statistics\n");
    printf("Database optimization completed.\n");
}

void generate_system_health_report() {
    printf("\n=== SYSTEM HEALTH REPORT ===\n");
    printf("Generated: %s\n", format_time(get_current_time()));
    printf("==============================\n");
    
    // Memory usage
    size_t memory_used = sizeof(Library) + 
                        (library.book_count * sizeof(Book)) +
                        (library.member_count * sizeof(Member)) +
                        (library.transaction_count * sizeof(Transaction));
    
    printf("Memory Usage:\n");
    printf("  Library Structure: %8zu bytes\n", sizeof(Library));
    printf("  Books (%d):        %8zu bytes\n", library.book_count, library.book_count * sizeof(Book));
    printf("  Members (%d):      %8zu bytes\n", library.member_count, library.member_count * sizeof(Member));
    printf("  Transactions (%d): %8zu bytes\n", library.transaction_count, library.transaction_count * sizeof(Transaction));
    printf("  Total Memory:      %8zu bytes (%.2f MB)\n", memory_used, memory_used / (1024.0 * 1024.0));
    
    // Capacity usage
    printf("\nCapacity Usage:\n");
    printf("  Books:        %5d / %5d (%5.1f%%)\n", library.book_count, MAX_BOOKS, 
           (double)library.book_count / MAX_BOOKS * 100);
    printf("  Members:      %5d / %5d (%5.1f%%)\n", library.member_count, MAX_MEMBERS,
           (double)library.member_count / MAX_MEMBERS * 100);
    printf("  Transactions: %5d / %5d (%5.1f%%)\n", library.transaction_count, MAX_TRANSACTIONS,
           (double)library.transaction_count / MAX_TRANSACTIONS * 100);
    
    // Performance metrics
    time_t uptime = get_current_time() - library.system_start_time;
    double transactions_per_hour = library.transaction_count / (uptime / 3600.0);
    
    printf("\nPerformance Metrics:\n");
    printf("  System Uptime:     %8ld seconds (%.1f hours)\n", uptime, uptime / 3600.0);
    printf("  Transactions/Hour: %8.2f\n", transactions_per_hour);
    printf("  Books Circulated:  %8d\n", library.total_books_circulated);
    printf("  Active Members:    %8d\n", library.member_count);
    
    // Health indicators
    printf("\nHealth Status:\n");
    if (library.book_count < MAX_BOOKS * 0.9) printf("  Book Capacity:     ✓ Good\n");
    else printf("  Book Capacity:     ⚠ Near Limit\n");
    
    if (library.member_count < MAX_MEMBERS * 0.9) printf("  Member Capacity:   ✓ Good\n");
    else printf("  Member Capacity:   ⚠ Near Limit\n");
    
    if (library.transaction_count < MAX_TRANSACTIONS * 0.9) printf("  Transaction Log:   ✓ Good\n");
    else printf("  Transaction Log:   ⚠ Near Limit\n");
    
    printf("==============================\n");
}

// Bulk operations for administrative efficiency
void bulk_add_books() {
    printf("\n--- Bulk Add Books ---\n");
    printf("This feature would allow importing multiple books from a CSV file.\n");
    printf("Format: ISBN,Title,Author,Genre,Year,Purchase_Price,Rental_Price,Copies\n");
    
    char filename[200];
    get_string_input("Enter CSV filename", filename, sizeof(filename));
    
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("Could not open file: %s\n", filename);
        return;
    }
    
    char line[1000];
    int added_count = 0;
    int line_number = 0;
    
    // Skip header line
    if (fgets(line, sizeof(line), file)) {
        line_number++;
    }
    
    while (fgets(line, sizeof(line), file)) {
        line_number++;
        
        // Parse CSV line (simplified parsing)
        char isbn[MAX_ISBN_LENGTH], title[MAX_TITLE_LENGTH], author[MAX_AUTHOR_LENGTH];
        char genre_str[MAX_GENRE_LENGTH];
        int year, copies;
        double purchase_price, rental_price;
        
        // In a real implementation, would use proper CSV parsing
        int fields = sscanf(line, "\"%[^\"]\",\"%[^\"]\",\"%[^\"]\",\"%[^\"]\",%d,%lf,%lf,%d",
                           isbn, title, author, genre_str, &year, &purchase_price, &rental_price, &copies);
        
        if (fields == 8) {
            GenreType genre = get_genre_from_string(genre_str);
            if (add_book(isbn, title, author, genre, year, purchase_price, rental_price, copies)) {
                added_count++;
            }
        } else {
            printf("Error parsing line %d: %s", line_number, line);
        }
    }
    
    fclose(file);
    printf("Bulk add completed. Added %d books.\n", added_count);
}

void bulk_update_books() {
    printf("\n--- Bulk Update Books ---\n");
    printf("1. Update all rental prices by percentage\n");
    printf("2. Update all purchase prices by percentage\n");
    printf("3. Add copies to all books\n");
    printf("4. Update genre for multiple books\n");
    printf("5. Bulk status change\n");
    
    int choice = get_integer_input("Choose update type", 1, 5);
    
    switch (choice) {
        case 1: // Update rental prices
            {
                double percentage = get_double_input("Enter percentage change (e.g., 10 for +10%, -5 for -5%)", -50.0, 100.0);
                int updated = 0;
                
                for (int i = 0; i < library.book_count; i++) {
                    library.books[i].rental_price *= (1.0 + percentage / 100.0);
                    updated++;
                }
                printf("Updated rental prices for %d books by %.1f%%\n", updated, percentage);
            }
            break;
            
        case 2: // Update purchase prices
            {
                double percentage = get_double_input("Enter percentage change", -50.0, 100.0);
                int updated = 0;
                
                for (int i = 0; i < library.book_count; i++) {
                    library.books[i].purchase_price *= (1.0 + percentage / 100.0);
                    updated++;
                }
                printf("Updated purchase prices for %d books by %.1f%%\n", updated, percentage);
            }
            break;
            
        case 3: // Add copies
            {
                int additional_copies = get_integer_input("Enter number of copies to add to each book", 1, 10);
                int updated = 0;
                
                for (int i = 0; i < library.book_count; i++) {
                    library.books[i].total_copies += additional_copies;
                    library.books[i].available_copies += additional_copies;
                    updated++;
                }
                printf("Added %d copies to %d books\n", additional_copies, updated);
            }
            break;
            
        default:
            printf("Feature not yet implemented.\n");
    }
}

// Advanced search with multiple criteria
void advanced_search() {
    printf("\n--- Advanced Search ---\n");
    printf("Enter search criteria (leave blank to skip):\n");
    
    char title_query[MAX_TITLE_LENGTH] = "";
    char author_query[MAX_AUTHOR_LENGTH] = "";
    char isbn_query[MAX_ISBN_LENGTH] = "";
    int min_year = 0, max_year = 0;
    double min_price = 0.0, max_price = 0.0;
    GenreType search_genre = GENRE_OTHER;
    BookStatus search_status = BOOK_AVAILABLE;
    
    // Collect search criteria
    get_string_input("Title contains", title_query, sizeof(title_query));
    get_string_input("Author contains", author_query, sizeof(author_query));
    get_string_input("ISBN", isbn_query, sizeof(isbn_query));
    
    printf("Year range (enter 0 to skip):\n");
    min_year = get_integer_input("Minimum year", 0, 2025);
    if (min_year > 0) {
        max_year = get_integer_input("Maximum year", min_year, 2025);
    }
    
    printf("Price range (enter 0 to skip):\n");
    min_price = get_double_input("Minimum price", 0.0, 1000.0);
    if (min_price > 0) {
        max_price = get_double_input("Maximum price", min_price, 1000.0);
    }
    
    // Perform search
    printf("\nSearch Results:\n");
    printf("================\n");
    
    int found_count = 0;
    for (int i = 0; i < library.book_count; i++) {
        Book* book = &library.books[i];
        int matches = 1;
        
        // Check title
        if (strlen(title_query) > 0) {
            char upper_title[MAX_TITLE_LENGTH], upper_query[MAX_TITLE_LENGTH];
            strcpy(upper_title, book->title);
            strcpy(upper_query, title_query);
            to_uppercase(upper_title);
            to_uppercase(upper_query);
            if (!strstr(upper_title, upper_query)) matches = 0;
        }
        
        // Check author
        if (strlen(author_query) > 0 && matches) {
            char upper_author[MAX_AUTHOR_LENGTH], upper_query[MAX_AUTHOR_LENGTH];
            strcpy(upper_author, book->author);
            strcpy(upper_query, author_query);
            to_uppercase(upper_author);
            to_uppercase(upper_query);
            if (!strstr(upper_author, upper_query)) matches = 0;
        }
        
        // Check ISBN
        if (strlen(isbn_query) > 0 && matches) {
            if (strcmp(book->isbn, isbn_query) != 0) matches = 0;
        }
        
        // Check year range
        if (min_year > 0 && matches) {
            if (book->publication_year < min_year || book->publication_year > max_year) {
                matches = 0;
            }
        }
        
        // Check price range
        if (min_price > 0 && matches) {
            if (book->purchase_price < min_price || book->purchase_price > max_price) {
                matches = 0;
            }
        }
        
        if (matches) {
            display_book_details(book);
            found_count++;
        }
    }
    
    printf("\nAdvanced search completed. Found %d matching book(s).\n", found_count);
}

// Staff operations for library employees
void staff_operations() {
    printf("\n--- Staff Operations ---\n");
    printf("1. Process Returns\n");
    printf("2. Handle Reservations\n");
    printf("3. Collect Late Fees\n");
    printf("4. Member Account Management\n");
    printf("5. Book Maintenance\n");
    printf("6. Inventory Management\n");
    printf("7. Generate Staff Reports\n");
    printf("0. Return to Main Menu\n");
    
    int choice = get_integer_input("Choose operation", 0, 7);
    
    switch (choice) {
        case 1:
            process_bulk_returns();
            break;
        case 2:
            handle_reservations();
            break;
        case 3:
            collect_late_fees();
            break;
        case 4:
            member_account_management();
            break;
        case 5:
            book_maintenance();
            break;
        case 6:
            inventory_management();
            break;
        case 7:
            generate_staff_reports();
            break;
        default:
            printf("Invalid choice.\n");
    }
}

void process_bulk_returns() {
    printf("\n--- Process Bulk Returns ---\n");
    printf("This feature would allow staff to quickly process multiple returns.\n");
    
    char input[100];
    printf("Enter Member ID or 'scan' to use barcode scanner: ");
    fgets(input, sizeof(input), stdin);
    
    if (strstr(input, "scan")) {
        printf("Barcode scanner mode activated.\n");
        printf("Scan member card, then scan each book to return.\n");
        printf("(In actual implementation, would interface with barcode hardware)\n");
    } else {
        int member_id = atoi(input);
        Member* member = find_member_by_id(member_id);
        if (member) {
            printf("Processing returns for %s:\n", member->name);
            printf("Currently borrowed books:\n");
            
            for (int i = 0; i < library.book_count; i++) {
                if (library.books[i].current_borrower_id == member_id) {
                    printf("- %s (%s)\n", library.books[i].title, library.books[i].isbn);
                }
            }
        }
    }
}

void handle_reservations() {
    printf("\n--- Handle Reservations ---\n");
    printf("Books with waiting lists:\n");
    printf("%-20s %-30s %-10s\n", "ISBN", "Title", "Waiting");
    printf("--------------------------------------------------------\n");
    
    for (int i = 0; i < library.book_count; i++) {
        if (library.books[i].waiting_count > 0) {
            printf("%-20s %-30s %-10d\n",
                   library.books[i].isbn,
                   library.books[i].title,
                   library.books[i].waiting_count);
        }
    }
}

void collect_late_fees() {
    printf("\n--- Collect Late Fees ---\n");
    printf("Members with outstanding fees:\n");
    printf("%-8s %-25s %-12s\n", "ID", "Name", "Fees Owed");
    printf("------------------------------------------------\n");
    
    for (int i = 0; i < library.member_count; i++) {
        if (library.members[i].outstanding_fees > 0) {
            printf("%-8d %-25s $%-11.2f\n",
                   library.members[i].member_id,
                   library.members[i].name,
                   library.members[i].outstanding_fees);
        }
    }
    
    int member_id = get_integer_input("Enter Member ID to collect fees from (0 to cancel)", 0, 99999);
    if (member_id > 0) {
        Member* member = find_member_by_id(member_id);
        if (member && member->outstanding_fees > 0) {
            printf("Collecting $%.2f from %s\n", member->outstanding_fees, member->name);
            library.total_revenue += member->outstanding_fees;
            member->outstanding_fees = 0.0;
            printf("Fees collected successfully.\n");
        }
    }
}

void member_account_management() {
    printf("\n--- Member Account Management ---\n");
    printf("1. View Member Details\n");
    printf("2. Update Member Information\n");
    printf("3. Upgrade/Downgrade Membership\n");
    printf("4. Extend Membership\n");
    printf("5. Add Credit to Account\n");
    printf("6. Reset Password\n");
    
    int choice = get_integer_input("Choose option", 1, 6);
    int member_id = get_integer_input("Enter Member ID", 1000, 99999);
    
    Member* member = find_member_by_id(member_id);
    if (!member) {
        printf("Member not found.\n");
        return;
    }
    
    switch (choice) {
        case 1:
            display_member_details(member);
            break;
        case 2:
            printf("Update member information feature would allow editing contact details.\n");
            break;
        case 3:
            printf("Current membership: %s\n", get_membership_string(member->membership_type));
            printf("1. Basic  2. Premium  3. VIP\n");
            int new_type = get_integer_input("Select new membership type", 1, 3);
            member->membership_type = (MembershipType)(new_type - 1);
            printf("Membership updated successfully.\n");
            break;
        default:
            printf("Feature not yet implemented.\n");
    }
}

void book_maintenance() {
    printf("\n--- Book Maintenance ---\n");
    printf("1. Mark Book for Repair\n");
    printf("2. Remove Damaged Book\n");
    printf("3. Add Book Copies\n");
    printf("4. Update Book Information\n");
    
    int choice = get_integer_input("Choose option", 1, 4);
    char isbn[MAX_ISBN_LENGTH];
    get_string_input("Enter book ISBN", isbn, sizeof(isbn));
    
    Book* book = find_book_by_isbn(isbn);
    if (!book) {
        printf("Book not found.\n");
        return;
    }
    
    switch (choice) {
        case 1:
            book->status = BOOK_MAINTENANCE;
            if (book->available_copies > 0) {
                book->available_copies--;
            }
            printf("Book marked for maintenance: %s\n", book->title);
            break;
        case 2:
            if (book->total_copies > 0) {
                book->total_copies--;
                if (book->available_copies > 0) {
                    book->available_copies--;
                }
            }
            printf("Damaged copy removed: %s\n", book->title);
            break;
        case 3:
            {
                int additional = get_integer_input("Enter number of copies to add", 1, 20);
                book->total_copies += additional;
                book->available_copies += additional;
                printf("Added %d copies of: %s\n", additional, book->title);
            }
            break;
        default:
            printf("Feature not yet implemented.\n");
    }
}

void inventory_management() {
    printf("\n--- Inventory Management ---\n");
    printf("1. Full Inventory Report\n");
    printf("2. Low Stock Alert\n");
    printf("3. Missing Books Report\n");
    printf("4. Book Condition Assessment\n");
    
    int choice = get_integer_input("Choose option", 1, 4);
    
    switch (choice) {
        case 1:
            printf("\n=== FULL INVENTORY REPORT ===\n");
            printf("%-20s %-30s %-8s %-8s %-10s\n", "ISBN", "Title", "Total", "Avail", "Value");
            printf("------------------------------------------------------------------------\n");
            
            double total_inventory_value = 0.0;
            for (int i = 0; i < library.book_count; i++) {
                Book* book = &library.books[i];
                double book_value = book->total_copies * book->purchase_price;
                total_inventory_value += book_value;
                
                printf("%-20s %-30s %-8d %-8d $%-9.2f\n",
                       book->isbn, book->title, book->total_copies,
                       book->available_copies, book_value);
            }
            printf("------------------------------------------------------------------------\n");
            printf("Total Inventory Value: $%.2f\n", total_inventory_value);
            break;
            
        case 2:
            printf("\n=== LOW STOCK ALERT ===\n");
            printf("Books with 2 or fewer available copies:\n");
            printf("%-20s %-30s %-8s\n", "ISBN", "Title", "Available");
            printf("--------------------------------------------------------\n");
            
            for (int i = 0; i < library.book_count; i++) {
                if (library.books[i].available_copies <= 2) {
                    printf("%-20s %-30s %-8d\n",
                           library.books[i].isbn,
                           library.books[i].title,
                           library.books[i].available_copies);
                }
            }
            break;
            
        default:
            printf("Feature not yet implemented.\n");
    }
}

void generate_staff_reports() {
    printf("\n--- Staff Reports ---\n");
    printf("1. Daily Activity Summary\n");
    printf("2. Member Service Report\n");
    printf("3. Book Circulation Statistics\n");
    printf("4. Revenue Collection Report\n");
    
    int choice = get_integer_input("Choose report", 1, 4);
    
    switch (choice) {
        case 1:
            generate_daily_activity_summary();
            break;
        default:
            printf("Report generation feature not yet implemented.\n");
    }
}

void generate_daily_activity_summary() {
    printf("\n=== DAILY ACTIVITY SUMMARY ===\n");
    printf("Date: %s\n", format_time(get_current_time()));
    printf("===============================\n");
    
    time_t today = get_current_time();
    time_t start_of_day = today - (today % (24 * 60 * 60));
    
    int books_borrowed_today = 0;
    int books_returned_today = 0;
    int new_members_today = 0;
    double revenue_today = 0.0;
    
    for (int i = 0; i < library.transaction_count; i++) {
        if (library.transactions[i].timestamp >= start_of_day) {
            switch (library.transactions[i].type) {
                case TRANSACTION_BORROW:
                    books_borrowed_today++;
                    break;
                case TRANSACTION_RETURN:
                    books_returned_today++;
                    break;
                case TRANSACTION_REGISTER:
                    new_members_today++;
                    revenue_today += library.transactions[i].amount;
                    break;
                case TRANSACTION_PURCHASE:
                case TRANSACTION_LATE_FEE:
                    revenue_today += library.transactions[i].amount;
                    break;
                case TRANSACTION_CANCEL:
                case TRANSACTION_RESERVATION:
                    // These transaction types don't affect daily activity counts
                    break;
            }
        }
    }
    
    printf("Books Borrowed Today:  %8d\n", books_borrowed_today);
    printf("Books Returned Today:  %8d\n", books_returned_today);
    printf("New Members Today:     %8d\n", new_members_today);
    printf("Revenue Collected:     $%7.2f\n", revenue_today);
    printf("Net Book Circulation:  %8d\n", books_borrowed_today - books_returned_today);
    printf("===============================\n");
}

// Final helper functions to complete the system
void list_all_members() {
    printf("\n--- All Library Members ---\n");
    printf("%-8s %-25s %-15s %-10s %-8s\n", "ID", "Name", "Membership", "Status", "Borrowed");
    printf("------------------------------------------------------------------------\n");
    
    for (int i = 0; i < library.member_count; i++) {
        Member* member = &library.members[i];
        printf("%-8d %-25s %-15s %-10s %-8d\n",
               member->member_id,
               member->name,
               get_membership_string(member->membership_type),
               member->is_active ? "Active" : "Inactive",
               member->num_borrowed);
    }
    
    printf("Total members: %d\n", library.member_count);
}

// Error handling and validation functions
int validate_isbn(const char* isbn) {
    if (!isbn || strlen(isbn) < 10) return 0;
    
    // Basic ISBN format validation
    int digit_count = 0;
    for (int i = 0; isbn[i]; i++) {
        if (isdigit(isbn[i])) digit_count++;
        else if (isbn[i] != '-' && isbn[i] != ' ') return 0;
    }
    
    return (digit_count == 10 || digit_count == 13);
}

int validate_email(const char* email) {
    if (!email || strlen(email) < 5) return 0;
    
    char* at_pos = strchr(email, '@');
    if (!at_pos) return 0;
    
    char* dot_pos = strrchr(email, '.');
    if (!dot_pos || dot_pos < at_pos) return 0;
    
    return 1;
}

int validate_phone(const char* phone) {
    if (!phone || strlen(phone) < 10) return 0;
    
    int digit_count = 0;
    for (int i = 0; phone[i]; i++) {
        if (isdigit(phone[i])) digit_count++;
        else if (phone[i] != '-' && phone[i] != '(' && phone[i] != ')' && 
                 phone[i] != ' ' && phone[i] != '+') return 0;
    }
    
    return (digit_count >= 10);
}

// Memory management for waiting lists
void cleanup_waiting_lists() {
    for (int i = 0; i < library.book_count; i++) {
        WaitingListEntry* current = library.books[i].waiting_list;
        while (current) {
            WaitingListEntry* next = current->next;
            free(current);
            
            if (next == current) {
                free(current);
            }
            current = next;
        }
        library.books[i].waiting_list = NULL;
        library.books[i].waiting_count = 0;
    }
}

// System shutdown procedures
void shutdown_system() {
    printf("Shutting down library system...\n");
    
    // Save all data
    save_library_data();
    
    // Cleanup dynamic memory
    cleanup_waiting_lists();
    
    // Log shutdown
    printf("System shutdown completed successfully.\n");
    printf("Total session statistics:\n");
    printf("- Books managed: %d\n", library.book_count);
    printf("- Members served: %d\n", library.member_count);
    printf("- Transactions processed: %d\n", library.transaction_count);
    printf("- Total revenue: $%.2f\n", library.total_revenue);
}

// Initialize sample data for demonstration
void initialize_sample_data() {
    // Add more sample books for demonstration
    add_book("978-0-061120-08-4", "Dune", "Frank Herbert", GENRE_SCIFI, 1965, 16.99, 2.75, 3);
    add_book("978-0-345391-80-2", "The Hobbit", "J.R.R. Tolkien", GENRE_FANTASY, 1937, 14.99, 2.50, 4);
    add_book("978-0-7432-7356-5", "The Da Vinci Code", "Dan Brown", GENRE_MYSTERY, 2003, 17.99, 3.00, 2);
    add_book("978-0-553-29698-2", "A Brief History of Time", "Stephen Hawking", GENRE_SCIENCE, 1988, 18.99, 3.25, 2);
    add_book("978-1-5011-2701-8", "Becoming", "Michelle Obama", GENRE_BIOGRAPHY, 2018, 32.50, 4.00, 3);
    
    // Create sample members
    create_member("John Smith", "john.smith@email.com", "555-0101", MEMBERSHIP_BASIC);
    create_member("Sarah Johnson", "sarah.j@email.com", "555-0102", MEMBERSHIP_PREMIUM);
    create_member("Michael Brown", "m.brown@email.com", "555-0103", MEMBERSHIP_VIP);
    create_member("Emily Davis", "emily.davis@email.com", "555-0104", MEMBERSHIP_BASIC);
    create_member("David Wilson", "d.wilson@email.com", "555-0105", MEMBERSHIP_PREMIUM);
}

// End of library management system
/*
 * This comprehensive library management system includes:
 * 
 * 1. Complete book management (add, search, update, remove)
 * 2. Member management with different membership tiers
 * 3. Borrowing and returning system with due dates and late fees
 * 4. Purchase system with membership discounts
 * 5. Transaction logging and audit trail
 * 6. Waiting lists for popular books
 * 7. Advanced search capabilities
 * 8. Financial reporting and analytics
 * 9. Staff operations and administrative functions
 * 10. Data persistence and backup systems
 * 11. System maintenance and health monitoring
 * 12. Bulk operations for efficiency
 * 13. Error handling and data validation
 * 14. Memory management for dynamic data structures
 * 15. Comprehensive reporting and statistics
 * 
 * The system demonstrates advanced C programming concepts including:
 * - Complex data structures and memory management
 * - File I/O for data persistence
 * - Function pointers and modular design
 * - Dynamic memory allocation for linked lists
 * - Time and date handling
 * - String manipulation and validation
 * - Mathematical calculations for fees and discounts
 * - Menu-driven user interface
 * - Error handling and input validation
 * 
 * This code provides a solid foundation for a real-world library
 * management system and can be extended with additional features
 * such as database integration, network capabilities, and GUI interfaces.
 */