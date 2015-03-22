from Tkinter import *
from events import mouseEntered, mouseLeft

class About:
    def __init__(self,parent):
        self.container1 = Frame(parent, relief=GROOVE, background='white', highlightbackground="black", highlightthickness=5)
        self.container1.pack(fill=BOTH, expand=YES)

        # Display Developer's Image
        #self.photo = base64.encodestring(open("gui/images/Sajjan.gif").read())
        self.photo = PhotoImage(file="gui/images/Sajjan.gif")
        #self.photoimage = PhotoImage(data=self.photo)
        title1 = Label(self.container1, text="About the Developer", background='white', font='Verdana 14 bold underline')
        title1.pack()
        pic = Label(self.container1, image=self.photo, bg="black", cursor="hand2")
        pic.pack(padx=10, pady=10)
        # Displays details about the Developer
        msg1 = Message(self.container1, text="Name : Sajjan Bhattarai\n"
                "Faculty: Computer Networking & IT Security\n"
                "Year: 3\n"
                "Group: L3N3\n"
                "Project: Final Year Project\n"
                "University: London Metropolitan University", relief=GROOVE, width=280, background='white')
        msg1.pack(padx=10, pady=10)

        # Displays information about the program
        global title2
        title2 = Label(self.container1, text="About the Program", background='white', font='Verdana 14 bold underline')
        title2.configure(cursor="hand2")
        title2.bind("<1>", lambda event: self.aboutpro())
        title2.bind("<Enter>", mouseEntered)
        title2.bind("<Leave>", mouseLeft)
        title2.pack()
        self.display = 0
        self.msg2 = Message(self.container1, text="This program has been developed as a Final "
                "Year Project in BSc. Computer Networking and IT Security. "
                "It's main objective is to provide a simple and easy to understand "
                "user interface to the people who want to manage their WLAN infrastructure. "
                "The main users of this program are Networking students, network specialists, "
                "System Administrator, home users and so on.", relief=GROOVE, width = 280, background='white')
        

    def aboutpro(self):
        global title2
        if self.display == 0:
            self.msg2.pack()
            self.display = 1
            title2["foreground"] = "brown"
        else:
            self.msg2.pack_forget()
            self.display = 0
            title2["foreground"] = "black"
