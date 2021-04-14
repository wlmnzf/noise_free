import pydotplus
# from igraph import *
import re
import numpy as np
import json
import os
from functools import reduce
import angr
from angrutils import *

from bs4 import BeautifulSoup
# word_list = """sing sign gins who how dad add""".split()
#
key_dict = {}
def Getindex(elem):
    return elem[1]["index"]
#
# def word2key(search_str):
#     return ''.join(sorted(search_str))

def search(kw_str):
    return key_dict.get(kw_str, 'Not Found!')
#
# # print(search('gnis'))
# # print(search('ohw'))
# # print(search('abc'))

# class Node:
#     def __init__(self, shape, label, name, cluster,index=-1):
#         self.shape = shape
#         self.label = label
#         self.name = name
#         self.cluster=cluster
#         self.index=index


all_file_list =[]

def get_all_filepath(dir):
    parents = os.listdir(dir)
    for parent in parents:
        child = os.path.join(dir,parent)
        if os.path.isdir(child):
            # get_all_filepath(child)
            continue
        else:
            suffix = os.path.splitext(child)[1]
            #print(suffix)
            if suffix ==".out":
                all_file_list.append(child)

def Node(index,label,name,table,belongfunc,func,functype,insn,feature,labelx):
    node={}
    node["label"]=label
    node["name"]=name
    node["index"]=index
    node["label_parsed"]=table
    node["belongfunc"]=belongfunc
    node["func"]=func
    node["functype"]=functype
    node["insn"]=insn
    node["feature"]=feature
    node["labelx"]=labelx
    return node


def Edge(fromnode, tonode, color,style,flag=-1):
    edge={}
    edge["fromnode"] = fromnode
    edge["tonode"] = tonode
    edge["color"] = color
    edge["style"]=style
    edge["flag"]=flag
    return edge
        


def bfs(visited, queue, node):
  main_block=[]
  visited.append(node)
  queue.append(node)

  while queue:
    s = queue.pop(0)
    # print ("(")
    # for i in s.predecessors():
    #     print(i["name"])
    #     break
    # print(","+s["name"]+")", end = " ")
    main_block.append(s)
    # print(s["name"])

    for neighbour in s.successors():
      if neighbour not in visited:
        visited.append(neighbour)
        queue.append(neighbour)

  return main_block


def adj_matrix(new_edgelist,new_index_dict,new_node_dict):
    reorder={}
    orderindex=0
    for key,value in sorted(new_node_dict.items(),key=lambda item:Getindex(item)):
        reorder[value["index"]]=orderindex
        orderindex+=1

    matrix=np.zeros((len(new_node_dict),len(new_node_dict)))

    style_dict={}
    style_index=1
    for edge in new_edgelist:
        code=0
        if edge["color"]+edge["style"] in style_dict:
            code=style_dict[edge["color"]+edge["style"]]
        else:
            style_dict[edge["color"]+edge["style"]]=style_index
            code=style_index
            style_index+=1
            
        matrix[reorder[edge["fromnode"]],reorder[edge["tonode"]]]=code

    # print(matrix)
    return matrix


def getnode(path):
        mul=0
        G=pydotplus.graphviz.graph_from_dot_file(path)
        # g = Graph(directed=True)

        edges=G.obj_dict["edges"]
        nodes=G.obj_dict["nodes"]

        start_main=[]
        node_dict={}
        index_dict={}

        edgelist=[]
        for edge in edges:
            pt=edges[edge][0]["points"]
            attr=edges[edge][0]["attributes"]
            color="black"
            style="straight"
            if(len(attr)>0 and "color" in attr):
                color=attr["color"]
            if(len(attr)>0 and "style" in attr):
                style=attr["style"]

            edge=Edge(int(pt[0]),int(pt[1]),color,style)
            # key_dict.setdefault(int(pt[0]), []).append(edge)
            # g.add_edge(pt[0], pt[1])
            edgelist.append(edge)


        for key in nodes:
            if(key=="graph" or key=="node"):
                continue
            cur_node=nodes[key][0]
            nodeindex=int(key)

            soup = BeautifulSoup(cur_node["attributes"]["label"],"html.parser")
            tables = soup.findAll("table")
            table = tables[0]
            rows = table.findAll("tr")
            name=rows[0].findAll('td')[0].contents[0]
            # for row in rows:
            #     tds = row.findAll('td')
            #     if(len(tds)==4):
            #         countrycode = tds[1].string
            #         timezone = tds[2].string
            label=0
            if(len(tables)==2):
                table2=tables[1]
                last_block_index=-1
                block_index=-1
                
                rows=table2.findAll("tr")
                nodenamelist=[]
                for rowindex in range(len(rows)):
                    cur_row=rows[rowindex]
                    cells=cur_row.findAll('td')
                    
                    insn=""
                    for cellindex in range(len(cells)):
                        if(len(cells[cellindex].contents)>0):
                            insn+="".join(cells[cellindex].contents[0].split())
                            insn+=" "
                    insn=insn.strip()

                    if(insn.find("clflush")>=0 or insn.find("rdtsc")>=0 or insn.find("0x6025e0")>=0):
                        label=1
                    node=""
                    nodename=cur_row.text.split(':')[0].strip()[2:]
                    nodename=trim(nodename)
                    nodenamelist.append(nodename)
                    
                
                record_file_path="/mnt/d/WSL/noise/src0.c.out.txt"

                branch_misses_feature=0.0001
                cache_misses_feature=0.0001
                L1_dcache_load_misses_feature=0.0001
                L1_dcache_loads_feature=0.0001
                L1_dcache_stores_feature=0.0001
                L1_icache_load_misses_feature=0.0001
                LLC_load_misses_feature=0.0001
                LLC_loads_feature=0.0001
                LLC_store_misses_feature=0.0001
                LLC_stores_feature=0.0001
                branch_load_misses_feature=0.0001

                fo = open(record_file_path, "r+")
                for line in fo.readlines():                          #依次读取每行  
                            line = line.strip()                             #去掉每行头尾空白  
                            
                            line=' '.join(line.split()).split()
                            if(line[5] in nodenamelist ):
                                # feature_index=reorder[name_dict[line[5]]["index"]]
                                if(line[4].find("branch-misses")>=0):
                                    branch_misses_feature+=1
                                if(line[4].find("cache-misses")>=0):
                                    cache_misses_feature+=1
                                if(line[4].find("L1-dcache-load-misses")>=0):
                                    L1_dcache_load_misses_feature+=1
                                if(line[4].find("L1-dcache-loads")>=0):
                                    L1_dcache_loads_feature+=1

                                if(line[4].find("L1-dcache-stores")>=0):
                                    L1_dcache_stores_feature+=1
                                if(line[4].find("L1-icache-load-misses")>=0):
                                    L1_icache_load_misses_feature+=1
                                # if(line[4].find("L1-dcache-load-misses")>=0):
                                #     L1-dcache-load-misses_feature+=1
                                if(line[4].find("LLC-load-misses")>=0):
                                    LLC_load_misses_feature+=1

                                if(line[4].find("LLC-loads")>=0):
                                    LLC_loads_feature+=1
                                if(line[4].find("LLC-store-misses")>=0):
                                    LLC_store_misses_feature+=1
                                if(line[4].find("LLC-stores")>=0):
                                    LLC_stores_feature+=1
                                if(line[4].find("branch-load-misses")>=0):
                                    branch_load_misses_feature+=1
                            # break
                fo.close()
                feat=[0,0,0,0,0,0,0,0,0,0,0]
                feat[0]=branch_misses_feature
                feat[1]=cache_misses_feature
                feat[2]=L1_dcache_load_misses_feature
                feat[3]=L1_dcache_loads_feature
                feat[4]=L1_dcache_stores_feature
                feat[5]=L1_icache_load_misses_feature
                feat[6]=LLC_load_misses_feature
                feat[7]=LLC_loads_feature
                feat[8]=LLC_store_misses_feature
                feat[9]=LLC_stores_feature
                feat[10]=branch_load_misses_feature

                # txt='<TABLE BORDER="0" CELLPADDING="1" ALIGN="LEFT"><TR>'
                # txt+="<TD>"+str(branch_misses_feature)+"</TD>"
                # txt+="<TD>:"+str(cache_misses_feature)+"</TD>"
                # txt+="<TD>:"+str(L1_dcache_load_misses_feature)+"</TD>"
                # txt+="<TD>:"+str(L1_dcache_loads_feature)+"</TD>"
                # txt+="<TD>:"+str(L1_dcache_stores_feature)+"</TD>"
                # txt+="<TD>:"+str(L1_icache_load_misses_feature)+"</TD>"
                # txt+="<TD>:"+str(LLC_load_misses_feature)+"</TD>"
                # txt+="<TD>:"+str(LLC_loads_feature)+"</TD>"
                # txt+="<TD>:"+str(LLC_store_misses_feature)+"</TD>"
                # txt+="<TD>:"+str(LLC_stores_feature)+"</TD>"
                # txt+="<TD>:"+str(branch_load_misses_feature)+"</TD>"
                # txt+="</TR></TABLE>"

                # G.obj_dict["nodes"][key][0]["attributes"]["label"]=G.obj_dict["nodes"][key][0]["attributes"]["label"].replace("<{","<{"+txt+"|")

# index,label,name,table,belongfunc,func,functype,insn,feature,labelx
            node = Node(nodeindex,cur_node["attributes"]["label"],name,tables,"","","","",feat,label)
            if(node["name"] in node_dict):
                for tmp_edge_index in range(len(edgelist)):
                    if(edgelist[tmp_edge_index]["fromnode"]==nodeindex):
                        edgelist[tmp_edge_index]["fromnode"]=node_dict[node["name"]]["index"]
                    if(edgelist[tmp_edge_index]["tonode"]==nodeindex):
                        edgelist[tmp_edge_index]["tonode"]=node_dict[node["name"]]["index"]
                # node["name"] +="_"+str(mul)
                # mul+=1
            else:
                node_dict[node["name"]]=node
                index_dict[nodeindex]=node["name"]
                nodeindex+=1
            # g.add_vertices(node["name"])
            # print(node.name)
            # if(subgraphs[subgraph][i]["attributes"]["label"]=='"main"'):
            #     start_main.append(node)
        
        #index

        return edgelist,index_dict,node_dict


# print(break_addr)
def trim(s):
   if len(s) == 0:  # 字符串为空直接返回
      return ''
   elif s[0] != '0':  # 首尾不存在空格直接返回
      return s
   elif s[0] == '0':  # 字符串头存在空格则截断
      return trim(s[1:])


def splitblock(edgelist,index_dict,node_dict):
    new_node_dict={}
    new_index_dict={}
    new_index=len(index_dict)
    # node_dict.sort(key=Getindex)
    
    for key,value in sorted(node_dict.items(),key=lambda item:Getindex(item)):
        tables=node_dict[key]["label_parsed"]
        # print(tables)
        table1=tables[0]
        rows=table1.findAll("tr")
        cells=rows[0].findAll('td')
        if(len(cells[1].contents)>0):   
            node_dict[key]["belongfunc"]=str(cells[1].contents[0])
        if(len(cells[2].contents)>0):
            node_dict[key]["func"]=str(cells[2].contents[0])
        if(len(cells[3].contents)>0):
            node_dict[key]["functype"]=str(cells[3].contents[0])

        if(len(tables)==2):
            table2=tables[1]
            last_block_index=-1
            block_index=-1
            
            rows=table2.findAll("tr")
            for rowindex in range(len(rows)):
                cur_row=rows[rowindex]
                cells=cur_row.findAll('td')
                
                insn=""
                for cellindex in range(len(cells)):
                    if(len(cells[cellindex].contents)>0):
                        insn+="".join(cells[cellindex].contents[0].split())
                        insn+=" "
                insn=insn.strip()

                node=""
                nodename=cur_row.text.split(':')[0].strip()[2:]
                nodename="0x"+trim(nodename)

                if rowindex==0:
                    node=Node(node_dict[key]["index"],"",nodename,"",node_dict[key]["belongfunc"],node_dict[key]["func"],node_dict[key]["functype"],insn)
                    block_index=node["index"]
                else:                  
                    node=Node(new_index,"",nodename,"",node_dict[key]["belongfunc"],node_dict[key]["func"],node_dict[key]["functype"],insn)
                    new_index+=1
                
                
                if last_block_index>=0:
                    edge={}
                    edge["color"]="yellow"
                    edge["fromnode"]=last_block_index
                    edge["tonode"]=node["index"]
                    edge["style"]="straight"
                    edge["flag"]=1
                    edgelist.append(edge)

                    if(rowindex==len(rows)-1):   #last row
                        for edgeindex in range(len(edgelist)):
                            if(edgelist[edgeindex]["fromnode"]==block_index and edgelist[edgeindex]["flag"]==-1):
                                edgelist[edgeindex]["fromnode"]=node["index"]
                                edgelist[edgeindex]["flag"]=1


                new_node_dict[nodename]=node
                new_index_dict[node["index"]]=nodename
                last_block_index=node["index"]
        else:
            node_dict[key]["label_parsed"]=""
            node_dict[key]["label"]=""
            new_node_dict[node_dict[key]["name"]]=node_dict[key]
            new_index_dict[node_dict[key]["index"]]=node_dict[key]["index"]

    return edgelist,new_index_dict,new_node_dict           
                # print(cells)
        # for row in rows:
        #         tds = row.findAll('td')
        #         if(len(tds)==4):
        #             countrycode = tds[1].string
        #             timezone = tds[2].string




all_file_list=[]
get_all_filepath("/mnt/d/WSL/noise")
# print(all_file_list)
for path in all_file_list:
    print(path)
    proj = angr.Project(path, load_options={'auto_load_libs':False},
                        use_sim_procedures=True,
                        default_analysis_mode='symbolic')

    main = proj.loader.main_object.get_symbol("main")
    start_state = proj.factory.blank_state(addr=main.rebased_addr)
    cfg = proj.analyses.CFGEmulated(context_sensitivity_level=2,fail_fast=True, starts=[main.rebased_addr], initial_state=start_state,keep_state=True,state_add_options=angr.sim_options.refs,normalize=True)
    plot_cfg(cfg, path,format="dot", asminst=True, remove_imports=True, remove_path_terminator=True)  

    # print(path)
    edgelist,index_dict,node_dict=getnode(path+".dot")
    # edgelist = list(set(edgelist))
    run_function = lambda x, y: x if y in x else x + [y]
    edgelist=reduce(run_function, [[], ] + edgelist)

    mapindex={}
    mapindex_i=0
    for node in node_dict:
        mapindex[node_dict[node]["index"]]=mapindex_i
        mapindex_i+=1

    # new_edgelist,new_index_dict,new_node_dict=splitblock(edgelist,index_dict,node_dict)
    # matrix=adj_matrix(new_edgelist,new_index_dict,new_node_dict)

    import csv
    csvFile=open("./edges.csv",'w',newline='')
    try:
        writer=csv.writer(csvFile)
        writer.writerow(('id1','id2'))
        for i in edgelist:
            writer.writerow((mapindex[i["fromnode"]],mapindex[i["tonode"]]))
    finally:
        csvFile.close()

    csvFile=open("./features.csv",'w',newline='')
    try:
        writer=csv.writer(csvFile)
        writer.writerow(("node_id","feature_id","value"))
        for i in node_dict:
            for j in range(11):
                writer.writerow((mapindex[node_dict[i]["index"]],j,node_dict[i]["feature"][j]))
    finally:
        csvFile.close()

    csvFile=open("./target.csv",'w',newline='')
    try:
        writer=csv.writer(csvFile)
        writer.writerow(('node_id','target'))
        for i in node_dict:
            writer.writerow((mapindex[node_dict[i]["index"]],node_dict[i]["labelx"]))
    finally:
        csvFile.close()



    # np.save(path+".npy",matrix)
    # with open(path+'.index_dict.json','w',encoding='utf-8') as f:
    #     json.dump(new_index_dict,f,ensure_ascii=False)
    # # index_dict

    # # for i in new_node_dict:
    #     # new_node_dict[i]["label"]=""
    #     # new_node_dict["name"]=name
    #     # node["index"]=index
    #     # new_node_dict[i]["label_parsed"]=""
    #     # new_node_dict[i]["belongfunc"]=""
    #     # new_node_dict[i]["func"]=""
    #     # new_node_dict[i]["functype"]=""
    #     # new_node_dict[i]["insn"]=""
    # with open(path+'.node_dict.json','w',encoding='utf-8') as f:
    #     json.dump(new_node_dict,f,ensure_ascii=False)

