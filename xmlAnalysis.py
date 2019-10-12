#!/usr/bin/python
#-*-coding:utf-8-*- 

import xmltodict
import traceback
import time
import os
import json
from xml.etree import ElementTree


def getGlobalParam():

    cfg = ParseXml('allitems-cvrf-year-2019.xml')
    g_AllParam = cfg.getParam()
 
    return g_AllParam


class ParseXml(object):
 
    def __init__(self, filename):
        try:
            self.tree = ElementTree.parse(filename)
            self.root = self.tree.getroot()
            self.string = ElementTree.tostring(self.root, encoding='utf-8')
            self.AllParam = self.xmltodict(self.string)
        except:
            print("======ParseXml __init__ err======")
            print(traceback.format_exc())
            self.AllParam = None
 
    def xmltodict(self, string):
        return xmltodict.parse(string)
 
    def getParam(self):
        return self.AllParam
 
 
if __name__ == '__main__':
    suffix = ".json"
    directory = "./CVE-2019"

    param = getGlobalParam()
    for i in param:
        for j in param[i]:
            if j == 'ns2:Vulnerability':
                for k in param[i][j]:
                    cve_info = {}
                    references = []
                    if k['ns2:References'] == None:
                        references = ['No References']
                    else:
                        if type(k['ns2:References']['ns2:Reference']).__name__ == 'list':
                            for R in k['ns2:References']['ns2:Reference']:
                                reference = {}
                                reference['Description'] = R['ns2:Description']
                                reference['URL'] = R['ns2:URL']
                                references.append(reference)
                        elif type(k['ns2:References']['ns2:Reference']).__name__ == 'OrderedDict':
                            reference = {}
                            reference['Description'] = k['ns2:References']['ns2:Reference']['ns2:Description']
                            reference['URL'] = k['ns2:References']['ns2:Reference']['ns2:URL']
                            references.append(reference)
                        else:
                            print k['ns2:Title'] + "/" + type(k['ns2:References']['ns2:Reference']).__name__
                    cve_info['cve_detail'] = ""
                    if type(k['ns2:Notes']['ns2:Note']).__name__ == 'list':
                        if len(k['ns2:Notes']['ns2:Note']) == 3:
                            cve_info['add_time'] = k['ns2:Notes']['ns2:Note'][1]['#text']
                            cve_info['modify_time'] = k['ns2:Notes']['ns2:Note'][2]['#text']
                            cve_info['cve_detail_en'] = k['ns2:Notes']['ns2:Note'][0]['#text']                                                                
                        else:
                            cve_info['add_time'] = k['ns2:Notes']['ns2:Note'][1]['#text']
                            cve_info['cve_detail_en'] = k['ns2:Notes']['ns2:Note'][0]['#text']
                            
                    elif type(k['ns2:Notes']['ns2:Note']).__name__ == 'OrderedDict':
                        cve_info['cve_detail_en'] = k['ns2:Notes']['ns2:Note']['#text']
                        cve_info['cve_detail'] = '**保留**此候选人已由宣布新的安全问题时将使用它的组织或个人保留。 公布候选人之后，将提供该候选人的详细信息。'
                    else:
                        print  k['ns2:Title'] + "/" + type(k['ns2:Notes']['ns2:Note']).__name__
                    cve_info['cve_id'] = k['ns2:Title']

                    cve_info['edit_time'] = time.asctime( time.localtime(time.time()) )
                    cve_info['editor'] = "warcup"
                    cve_info['cve_categories'] = ["category1", "category2"]
                    cve_info['cve_risk_level'] = "determine"
                    cve_info['cve_name'] = "cve_name"
                    cve_info['cve_name_en'] = "cve_name_en"
                    cve_info['cve_code_detect_url'] = ""
                    cve_info['cve_code_exp_url'] = ""
                    cve_info['cve_code_des_url'] = ""
                    cve_info['cve_repaire'] = ""
                    cve_info['cve_repaire_en'] = ""
                    cve_info['cve_other_info'] = ""
                    cve_info['references'] = references
                    cve_info_json = json.dumps(cve_info)
                    newfile = cve_info['cve_id'] + suffix
                    if not os.path.exists(directory+'/'+newfile):
                        f = open(directory+'/'+newfile,'w') 
                        f.write(cve_info_json)
                        print newfile + " created."
                        f.close()
                    else:
                        print newfile + " already existed."
                    all_cve_file = "./CVE_ALL/CVE-2019.json"
                    f = open(all_cve_file,'a')
                    f.write(cve_info_json)
                    f.write('\n')
                    f.close()
                    
                    
                    

                       


