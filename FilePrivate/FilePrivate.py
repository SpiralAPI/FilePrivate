# @author:SpiralAPI

# Imports
from cryptography.fernet import Fernet
import tkinter as tk
import tkinter.filedialog as fd
import tkinter.messagebox as mb
import random
import string
import os
import shutil

# Variables
Files = list()

# Cryptography Handling
def RandomFileName():
    return (''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase, k=7)))

def ReturnFileExtension(FileName):
    return (os.path.splitext(FileName)[1])

def EncryptFiles(FileDataDict: dict, SavePath: str, Key: str):
    Encrypt = Fernet(Key)
    for FileName in FileDataDict:
            with open(SavePath + "/" + RandomFileName() + ReturnFileExtension(FileName) + ".fileprivate", "ab") as EncFile:
                EncFile.write(Encrypt.encrypt(FileDataDict[FileName]))
                EncFile.close()
            
def GenerateDecryptFolder(LoadPath: str, Key: str):
    CleanupDir()
    KeepRunning = True
    try:
        Decrypt = Fernet(Key)  
    except:
        KeepRunning = False
        mb.showerror(title="Invalid Password!", message="Password did not follow valid format. Make sure to use the generate password button if you haven't already.")

    if KeepRunning == True:
        Errored = False
        for filename in os.scandir(os.path.abspath(os.getcwd()) + "/EncryptedFiles"):
            if filename.is_file():
                with open(filename.path, "rb") as EncrypedFile:
                    fileError = False
                    try:
                        data = Decrypt.decrypt(EncrypedFile.read())
                    except:
                        fileError = True
                        Errored = True
                    if fileError == False:
                        with open(LoadPath + "\\'" + str(filename.name).replace(".fileprivate",""), "wb") as DecryptedFile:
                            DecryptedFile.write(data)
        if Errored == True:
            mb.showerror(title="Invalid Password for Some or All Files!", message="Invalid password was provided for some or all files. Any files thats password didn't match were not shown.")
        os.startfile(LoadPath)

def CleanupDir():
    LoadPath=os.path.abspath(os.getcwd()) + "/DecryptedFiles"
    for filename in os.listdir(LoadPath):
        file_path = os.path.join(LoadPath, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))

# UI Functionality
def OpenFiles():
    Files.clear()
    for selection in fd.askopenfiles(initialdir="/", filetypes=[("all files", "*.*")], parent=Root, title="Select files you wish to privatize."):
        Files.append(selection)
    FilesOpened.configure(text="File(s) Selected: " + str(len(Files)))

def GenRandomKey():
    KeyVar = Fernet.generate_key()
    KeyInput.delete(0, len(KeyInput.get()))
    KeyInput.insert(0, KeyVar)
    Root.clipboard_clear()
    Root.clipboard_append(KeyVar)
    Root.update()
    mb.showwarning(title="Random Password Copied", message="Your random password has been copied to your clipboard. Make sure to save this password somewhere safe. Losing it means you could lose access to your privatized files.")

def PrivatizeSelection():
    worked = True

    try:
        Fernet(KeyInput.get())
    except:
        worked = False
        mb.showerror(title="Invalid Password!", message="Password did not follow valid format. Make sure to use the generate password button if you haven't already.")

    if worked == True:
        if Files == list():
            mb.showerror(title="No Files Selected", message="No files were selected!")
        else:
            newDict = dict()
            for File in Files:
                head, filename = os.path.split(File.name)
                with open(str(File.name), "rb") as fileReadable:
                    newDict[filename] = fileReadable.read()
            EncryptFiles(newDict, os.path.abspath(os.getcwd()) + "/EncryptedFiles", KeyInput.get())
            Files.clear()
            FilesOpened.configure(text="File(s) Selected: " + str(len(Files)))

def ViewPrivatizedFiles():
    GenerateDecryptFolder(os.path.abspath(os.getcwd()) + "/DecryptedFiles", KeyInput.get())    

    

# GUI
Root = tk.Tk()

Root.geometry("300x400")
Root.title("FilePrivate")
Root.configure(background="#EFEFEF")
Root.resizable(False,False)

Title = tk.Label(Root, text="FilePrivate", font=("Arial", 35, "bold"), foreground="#e3a600")
Desc = tk.Label(Root, text="No bullshit file privacy using cryptography.", font=("Arial", 12), foreground="#000000")
Title.pack()
Desc.pack()

Space1 = tk.Label(Root, text="")
Space1.pack()

OpenBtn = tk.Button(Root, text="Open File(s) To Privatize", font=("Arial", 15, "bold"), background="#e3a600", highlightthickness=0, bd=0, command=OpenFiles)
FilesOpened = tk.Label(Root, text="File(s) Selected: 0", font=("Arial", 10), foreground="#000000")

OpenBtn.pack()
FilesOpened.pack()

Space2 = tk.Label(Root, text="")
Space2.pack()

SetKeyTxt = tk.Label(Root, text="Set Your Password:", font=("Arial", 15, "bold"), foreground="#e3a600")
SetKeyDesc = tk.Label(Root, text="Set the password used to encrypt and decrypt your files.", font=("Arial", 8), foreground="#000000")
SetKeyTxt.pack()
SetKeyDesc.pack()

KeyInput = tk.Entry(Root, width=25, font=("Arial", 12), bd=0, highlightthickness=0, background="#e3e3e3", foreground="#9c9c9c", justify=tk.CENTER)
KeyInput.insert(0, "enter your password here")
KeyInput.pack()

GenerateRandomKey = tk.Button(Root, text="Generate Random Password", font=("Arial", 10, "bold"), background="#9c9c9c", highlightthickness=0, bd=0, command=GenRandomKey)
GenerateRandomKey.pack()

Space3 = tk.Label(Root, text="")
Space3.pack()

ButtonFrame = tk.Frame()

PrivatizeSelectedFiles = tk.Button(ButtonFrame, text="Privatize", font=("Arial", 10, "bold"), background="#e3a600", highlightthickness=0, bd=0, width=10, command=PrivatizeSelection)
PrivatizeSelectedFiles.pack(side=tk.LEFT)

OpenPrivateFiles = tk.Button(ButtonFrame, text="View Files", font=("Arial", 10, "bold"), background="#e3a600", highlightthickness=0, bd=0, width=10, command=ViewPrivatizedFiles)
OpenPrivateFiles.pack(side=tk.LEFT)

CleanupButton = tk.Button(Root, text="Cleanup Decrypted Files", font=("Arial", 10, "bold"), background="#fc0335", highlightthickness=0, bd=0, width=21, command=CleanupDir)
ButtonFrame.pack()
CleanupButton.pack()

Root.mainloop()

CleanupDir()