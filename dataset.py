import csv
targetlists=[]
with open('/mnt/d/WSL/kmeans/target.csv')as f:
        f_csv = csv.reader(f)
        for row in f_csv:
            if int(row[1])==1:
                targetlists.append(int(row[0]))


dict_reverse={}
with open('/mnt/d/WSL/kmeans/edges.csv')as f:
        f_csv = csv.reader(f)
        for row in f_csv:
            dict_reverse[int(row[1])]=int(row[0])

# lists=[]
# max=-1
# with open('/mnt/d/WSL/kmeans/features.csv')as f:
#         f_csv = csv.reader(f)
#         # x=f.readlines()
#         for row in f_csv:
#             dict_reverse[int()]
#             dict_reverse[int(row[1])]=int(row[0]) 
        
lists=[]
lists=[0 for i in range(83)]
with open('/mnt/d/WSL/kmeans/features.csv')as f:
        f_csv = csv.reader(f)
        for row in f_csv:
            # print(row)
            lists[int(row[0])]+=float(row[2])
# print(lists)
for index in range(len(lists)):
    lists[index]=lists[index]/10

data=[index for index in range(len(lists)) if lists[index]>100]
print(data)