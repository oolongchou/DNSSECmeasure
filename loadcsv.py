import csv
import re
import pandas as pd

class domainload:
    result = {}
    chinaresult=[]
    header=['id','domain']

    def loadAlexa(self,filename):
        csvFile = open(filename, "r")
        reader = csv.reader(csvFile)
        text=''

        for item in reader:

            if re.match(r'\S*\.cn ', item[1]):
                self.chinaresult.append(item[1])

        outcsvFile = open("China.txt", "a+")

        for it in self.chinaresult:
            outcsvFile.writelines(it+",\n")


        print(type(self.chinaresult))
       # self.writecsv("CNdomain.csv",self.chinaresult)
        csvFile.close()
    def writecsv(self,filename,content):
        csvFile = open(filename, "w")
        writer = csv.DictWriter(csvFile,self.header)
        writer.writeheader()
        writer.writerows(content)

    def loadfile(self,filename):
        File = open(filename, "r")
        for line in File:
            print(line)

    def FindCNdomian(self):

        pass


