from gui import root
import sys
import traceback

def handle_exception(exc_type, exc_value, exc_traceback):
    """Handle uncaught exceptions"""
    error_msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    print(f"An error occurred:\n{error_msg}")
    
    # Log the error
    with open("error_log.txt", "a") as f:
        f.write(f"\n{'-'*50}\n")
        f.write(error_msg)

if __name__ == "__main__":
    # Set up global exception handler
    sys.excepthook = handle_exception
    
    try:
        print("Starting Security Headers Scanner...")
        print("GUI version running on: Tkinter")
        print("Web version available at: http://127.0.0.1:5000")
        root.mainloop()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)