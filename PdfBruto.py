#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pyPdf
from tqdm import *
import sys
import os.path
import datetime, time
import multiprocessing
import re
# pdfBruto test.pdf -f asd -ml 6

class PdfBruto:
    """Class used for PdfPassword cracking.
    
    Internal attributes:
    complete_list - Generated list
    pfile - pdf file to open
    maxlen - Max length of the password [don't use maxlen >6, unless u 
             want redicoulus computational time and a memory error can occur]
    param - String containing parameters used for creating wordlist
    
    """

    def __init__(self, pfile, maxlen = 5, param = "da", nproc = 4):
        """Starts the PdfBruto class.

        Keywords argument:
        pfile - Pdf file
        maxlen - Max complexity of the password [5 default]
        param - It is used for creating the wordlist:
                a for alphabetical characters
                A for capitalized alphabetical characters
                d for digits 
                s for symbols
                You need to pass them as a string composed by these chars i.e. 'aAd' or 'sdA'
                Sorting doesn't matter! ('aAd' == 'dAa')

        """
        
        if not re.match("^[asdA]+$", param): # Check if param matches the right pattern
            raise ValueError("invalid argument!") 
        
        self.complete_list = []
        self.pfile = pfile
        self.maxlen = maxlen
        self.param = param
        self.nproc = nproc
        # Start processes and bruteforce attack
        try:
            self.start()
        except KeyboardInterrupt as e:
            print "Quitting...\n"
            sys.exit(1)

    def start(self):
        """Create the processes and manage their work and life.
        
        
        """

        btime = datetime.datetime.now()
        self.complete_list = self.generate_list()
        dimlist = len(self.complete_list)
        print "La lista generata ha dimensione :", dimlist, "\nStarting ", self.nproc, " processes...\n"
        
        processes = []
        for i in range(self.nproc):
            delta = dimlist / self.nproc
            l = i * delta
            r = (i + 1) * delta
            p = multiprocessing.Process(target=self.brute, args=(self.complete_list[l:r],))
            processes.append(p)
            p.start()

        # Checking until calculation is done
        # When a process will find the password will exit with exitcode = 4.
        done = False
        while not done: #  Wait until the password is found or every process has failed
            for proc in processes[:]:
                time.sleep(1)
                print "\rWorking...."
                if proc.exitcode == 4:
                    done = True
                    break
                elif not proc.is_alive():
                    if len(processes) == 1:
                        done = True;
                        print "Cracking failed."
                    processes.remove(proc)

        etime = datetime.datetime.now()
        print "Total time elapsed for bruteforcing: ", etime - btime
        """# Kill any running processes
        for proc in processes:
            print "Killing processes"
            if proc.is_alive():
                proc.terminate()"""

    def generate_list(self):
        """Return a list composed by words between 1 and maxlen
        
        self.param represents the format of the wordlist used for bruteforcing
                a for alphabetical characters
                A for capitalized alphabetical characters
                d for digits 
                s for symbols
                You need to pass them as a string composed by this char i.e. 'aAd' or 'sdA'
                Sorting doesn't matter! ('aAd' == 'dAa')
        """

        maindict = {"a": 'abcdefghijklmnopqrstuvwxyz',
                    "A": 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
                    "d": '0123456789',
                    "s": "|£$%&()=?^[]@#-_</>"}

        clist = ""
        for char in self.param:
            clist += maindict[char]

        print "I caratteri selezionati sono :\n" + clist + "\n"
        complete_list = []
        for current in xrange(self.maxlen):
            a = [i for i in clist]
            for y in xrange(current):
                a = [x + i for i in clist for x in a]
            complete_list = complete_list + a
        print "Password list generated\n"
        return complete_list

    def brute(self, complete_list):
        """Attempt to crack the pdf file with the given list.

        When one of the password matches the pdf's password, the process will exit
        with the exitcode = 4. This is used to kill all the others running processes (as callback mechanism)
        """
        
        try:
            pdf = pyPdf.PdfFileReader(open(self.pfile))
            for password in complete_list:  # tqdm(complete_list) for bar
                if pdf.decrypt(password):
                    print "Password Found: '" + password + "'!\n"
                    sys.exit(4)
                    break
        except IOError as e:
            print "Unable to find the file: ", self.pfile
            sys.exit(1)


test = PdfBruto("test1.pdf", 5, "ad", 18)
