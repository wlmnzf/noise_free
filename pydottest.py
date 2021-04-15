# Python3 Program to print BFS traversal
# from a given source vertex. BFS(int s)
# traverses vertices reachable from s.
from collections import defaultdict
import csv 
# This class represents a directed graph
# using adjacency list representation
bfs_array=[]
class Graph:
 
    # Constructor
    def __init__(self):
 
        # default dictionary to store graph
        self.graph = defaultdict(list)
 
    # function to add an edge to graph
    def addEdge(self,u,v):
        self.graph[u].append(v)
 
    # Function to print a BFS of graph
    def BFS(self, s):
 
        # Mark all the vertices as not visited
        array_max=[]
        for index in self.graph:
            array_max.append(max(self.graph[index]))
            
        visited = [False] * (max(array_max) + 1)
 
        # Create a queue for BFS
        queue = []
 
        # Mark the source node as
        # visited and enqueue it
        queue.append(s)
        visited[s] = True
        
        
        while queue:
 
            # Dequeue a vertex from
            # queue and print it
            x=0
            queue_len=len(queue)
            while x<queue_len:
                s = queue.pop(0)
                bfs_array.append(s)
                print (s, end = " ")
    
                # Get all adjacent vertices of the
                # dequeued vertex s. If a adjacent
                # has not been visited, then mark it
                # visited and enqueue it
                for i in self.graph[s]:
                    if visited[i] == False:
                        queue.append(i)
                        visited[i] = True
                x=x+1
            print("\n")
 
# Driver code
 
# Create a graph given in
# the above diagram
g = Graph()
dict_reverse={}
with open('/mnt/d/WSL/noise/edges.csv')as f:
        f_csv = csv.reader(f)
        for row in f_csv:
            g.addEdge(int(row[0]), int(row[1]))
            # dict_reverse[int(row[1])]=int(row[0])

# g.addEdge(0, 2)
# g.addEdge(1, 2)
# g.addEdge(2, 0)
# g.addEdge(2, 3)
# g.addEdge(3, 3)
 
print ("Following is Breadth First Traversal"
                  " (starting from vertex 2)")
g.BFS(53) 
# print(bfs_array)
