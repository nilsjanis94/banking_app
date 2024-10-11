import login_window
import tkinter as tk


def main():
    root = tk.Tk()
    app = LoginApplication(root)

    # Example of adding a user 
    #app.add_user('admin', 'password')


    root.mainloop()

main()