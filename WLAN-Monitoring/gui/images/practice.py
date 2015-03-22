#import Image
#import ImageTk
from Tkinter import *



def new():
    wind = Toplevel()
    wind.geometry('600x600')               # This not work, why? 
    #imageFile2 = Image.open("someimage2.jpg")
    image2 = PhotoImage(file="WAP.gif")

    panel2 = Label(wind , image=image2)
    panel2.place(relx=0.0, rely=0.0)
    wind.mainloop()

master = Tk()
master.geometry('600x600')               # This work fine
#imageFile = Image.open("Sajjan.gif")
image1 = PhotoImage(file="Sajjan.gif")

panel1 = Label(master , image=image1)
panel1.place(relx=0.0, rely=0.0)
B = Button(master, text = 'New image', command = new).pack()
master.mainloop()
