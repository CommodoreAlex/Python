#!/usr/bin/env python3
import os
import logging
import subprocess

def create_group():
    group_name = 'librarians'
    try:
        # Check if the group exists
        subprocess.run(['getent', 'group', group_name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print(f"Group '{group_name}' doesn't exist, creating it now...")
        subprocess.run(['sudo', 'groupadd', group_name])

def add_user_to_group(user_name):
    group_name = 'librarians'
    try:
        # Add the user to the 'librarians' group
        subprocess.run(['sudo', 'usermod', '-aG', group_name, user_name], check=True)
        print(f"User '{user_name} added to group '{group_name}'.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to add user '{user_name} to group '{group_name}': {e}")

def set_log_permissions():
    log_file = '/var/library.log'

    try:
        # Change the group ownership of the log file to 'librarians'
        subprocess.run(['sudo', 'chown', ':librarians', log_file], check=True)

        # Set permissions so only the owner and group can read/write (660), others have no access
        subprocess.run(['sudo', 'chmod', '660', log_file], check=True)

        print(f"Permissions for '{log_file}' set to 660 (owner and group read/write).")
    except subprocess.CalledProcessError as e:
        print(f"Failed to set permissions for '{log_file}': {e}")

# Configure logging to write to a file
logging.basicConfig(filename='/var/library.log', level=logging.INFO)

def setup_logging():
    create_group() # Ensure 'librarians' group exists
    current_user = os.getlogin() # Get the current logged-in user
    add_user_to_group(current_user) # Add the current user to the 'librarians' group
    set_log_permissions() # Set the correct permissions for the log file

def clear_screen():
    os.system('clear')  # On Linux/MacOS

def view_books():
    try:
        with open("books.txt", "r") as file:
            books = file.readlines()

            if not books:  # If the file is empty
                print("\nNo books available!")
                logging.info("No books available to view.")
                return

            # Remove duplicates using set, then sort the books
            books = list(set(books))
            books.sort()

            print("\nHere are the available books: ")
            for i, book in enumerate(books, 1):  # Enumerating for numbering
                print(f"{i}. {book.strip()}")  # Clean up newlines
            logging.info("Books listed successfully.")
    except FileNotFoundError:
        print("\nThe library is empty! Add some books first.")
        logging.error("books.txt file not found. Library is empty.")
        menu()  # Return to the menu (ensure menu() exists)

def add_book():
    new_book = str(input("Enter the title of the book to add: "))

    try:
        # Read the existing books from the file to check for duplicates
        with open("books.txt", "r") as file:
            books = file.readlines()

        # Check if the new book already exists in the list
        if new_book + "\n" in books:
            print(f"\n'{new_book}' is already in the library.")
            logging.info(f"Attempted to add '{new_book}', but it already exists.")
            return

        # Open the books.txt file in append mode to add the new book
        with open("books.txt", "a") as file:
            file.write(new_book + "\n")

        # Create a new file for the book with its title
        filename = f"{new_book}.txt"
        with open(filename, "w") as book_file:
            book_file.write(f"This is the content of the book: {new_book}\n")  # You can customize this

        # Confirm the new book was added
        print(f"\n'{new_book}' has been added to the library.")
        logging.info(f"Book '{new_book}' added successfully to books.txt and created a new file.")
    except Exception as e:
        print(f"\nAn error has occurred while adding the book: {e}")
        logging.error(f"Error adding book '{new_book}': {e}")

def delete_book():
    try:
        # Reading the file and displaying books to the user
        with open("books.txt", "r") as file:
            books = file.readlines()

        if not books:  # If the file is empty
            print("\nNo books available to delete!")
            logging.info("No books available to delete.")
            return

        # Remove the duplicates using set, then sort the books
        books = list(set(books))
        books.sort()

        # Show the list of books to the user
        print("\nHere are the available books:")
        for i, book in enumerate(books, 1):
            print(f"{i}. {book.strip()}")

        # Ask the user to select the book to delete
        book_to_delete = int(input("\nEnter the number of the book to delete: ")) - 1

        # Check if the input is valid
        if book_to_delete < 0 or book_to_delete >= len(books):
            print("\nInvalid book number!")
            logging.warning("Invalid book number entered during delete operation.")
            return

        # Remove the selected book from the list
        del books[book_to_delete]

        # Rewrite the books back to the file without the deleted book
        with open("books.txt", "w") as file:
            file.writelines(books)

        print("\nThe book has been deleted successfully.")
        logging.info("Book deleted successfully from books.txt.")
    except FileNotFoundError:
        print("\nThe library is empty! Add some books first.")
        logging.error("books.txt file not found during delete operation.")
    except Exception as e:
        print(f"\nAn error occurred while deleting the book: {e}")
        logging.error(f"Error during book deletion: {e}")

def open_book():
    try:
        with open("books.txt", "r") as file:
            books = file.readlines()

        if not books:
            print("\nNo books available to open!")
            logging.info("No books available to open.")
            return

        # Show the list of available books
        print("\nHere are the available books: ")
        for i, book in enumerate(books, 1):
            print(f"{i}. {book.strip()}")

        # Ask the user to select a book to open
        book_to_open = int(input("\nEnter the number of the book to open: "))

        # Check if the input is valid
        if book_to_open < 1 or book_to_open > len(books):
            print("\nInvalid book number!")
            logging.warning("Invalid book number entered during open operation.")
            return

        # Get the book title and create a filename (assuming each book has its own file)
        book_title = books[book_to_open - 1].strip()  # Convert to a 0-based index
        filename = f"{book_title}.txt"

        # Attempt to open and read the book
        try:
            with open(filename, "r") as book_file:
                print(f"\nReading '{book_title}':\n")
                print(book_file.read())  # Display the contents of the book
            logging.info(f"Book '{book_title}' opened successfully.")
        except FileNotFoundError:
            print(f"\nThe book '{book_title}' does not exist. Please make sure it was added properly.")
            logging.error(f"File for book '{book_title}' not found.")
        except Exception as e:
            print(f"\nAn error occurred while opening the book: {e}")
            logging.error(f"Error during book open operation for '{book_title}': {e}")
    except FileNotFoundError:
        print("\nThe library is empty! Add some books first.")
        logging.error("books.txt file not found during open operation.")
    except Exception as e:
        print(f"\nAn error has occurred: {e}")
        logging.error(f"Error during open operation: {e}")

def menu():
    clear_screen()  # Clear screen before the menu displays
    while True:
        print("="*40)
        print("\nLibrary Management System")
        print("="*40)
        print("1. View Books")
        print("2. Add a Book")
        print("3. Delete a Book")
        print("4. Open a Book")
        print("5. Exit")
        print("="*40)

        try:
            choice = int(input("Enter your choice: "))
        except ValueError:
            print("\nInvalid Input! Please enter a number.")
            logging.warning("Invalid input entered during menu selection.")
            continue

        match choice:
            case 1:
                view_books()
            case 2:
                add_book()
            case 3:
                delete_book()
            case 4:
                open_book()
            case 5:
                print("\nGoodbye! ")
                logging.info("User exited the program.")
                return  # Exit the program gracefully.
            # Error handling
            case _:
                print("\nInvalid option! Please try again.")
                logging.warning("Invalid option selected in menu.")

# Call the setup function to congiure the permissions before logging
setup_logging()

# Present the menu to the user
menu()
