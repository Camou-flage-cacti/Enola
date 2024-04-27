# -*- coding: utf-8 -*-

""" Module for converting UVPROJX project format file
    @file
    pip install lxml
"""

import os
from lxml import objectify
import xml.etree.ElementTree as ET

class UVPROJXProject(object):
    """ Class for converting UVPROJX project format file
    """

    def __init__(self, path, xmlFile):
        self.path = path
        self.project = {}
        self.tmp = {}
        self.xmlFile = xmlFile
        xmltree = objectify.parse(xmlFile)
        self.root = xmltree.getroot()
        self.proj_root = ET.parse(xmlFile).getroot()

    def parseProject(self):
        """ Parses EWP project file for project settings
        """

        board_comp = "../Arm/Packs/Keil/V2M-MPS2_IOTKit_BSP/1.4.2/Boards/ARM/V2M-MPS2/Common/"       
        cmsis_comp = "../Arm/Packs/Keil/V2M-MPS2_IOTKit_BSP/1.4.2/CMSIS/Driver/" 
        RET_comp = "RTE/Device/IOTKit_CM33_FP/"

        self.project['name'] = self.root.Targets.Target.TargetName
        self.project['chip'] = str(self.root.Targets.Target.TargetOption.TargetCommonOption.Device)
        self.project['mems'] = self.root.Targets.Target.TargetOption.TargetCommonOption.Cpu
        self.project['defs'] = self.root.Targets.Target.TargetOption.TargetArmAds.Cads.VariousControls.Define.text.split(' ')
        self.project['srcs'] = []
        self.project['incs'] = []
        # for item in self.proj_root.findall('RTE/files'):
        #     for file in item.iter("file"):
        #         for instance in file.iter("instance"):
        #             self.project['incs'].append(instance.text)

        self.project['defs'].append("IOTKit_CM33_FP")

        for item_root in self.proj_root.findall('RTE'):
            # check apis
            for item in item_root.findall('apis'):
                for api in item.iter("api"):
                    for packages in api.iter("package"):
                        vendor = packages.get("vendor")
                        pkg_name = packages.get("name")
                        Cclass = api.get("Cclass")
                        Cgroup = api.get("Cgroup")
                        # print(Cclass)
                        if Cclass == "Board Support":
                            if Cgroup == "Buttons":
                                self.project['srcs'].append(board_comp+"Buttons_V2M-MPS2.c")
                            elif Cgroup == "Graphic LCD":
                                self.project['srcs'].append(board_comp+"GLCD_Fonts.c")
                                self.project['srcs'].append(board_comp+"GLCD_V2M-MPS2.c")
                            elif Cgroup == "LED":
                                self.project['srcs'].append(board_comp+"LED_V2M-MPS2.c")
                            elif Cgroup == "Touchscreen":
                                self.project['srcs'].append(board_comp+"Touch_V2M-MPS2.c")
                        elif Cclass == "CMSIS Driver":
                            if Cgroup == "USART":
                                self.project['srcs'].append(cmsis_comp+"USART_V2M-MPS2.c")

            # check components
            for item in item_root.findall('components'):
                for component in item.iter("component"):
                    for packages in component.iter("package"):
                        # tmp = "../Arm/Packs/"
                        # vendor = packages.get("vendor")
                        # pkg_name = packages.get("name")
                        Cclass = component.get("Cclass")
                        # print(Cclass)
                        # if vendor == "Keil":
                        #     tmp = tmp + vendor + "/" + pkg_name
                        # print(tmp)

            # check include files
            # for item in item_root.findall('files'):
            #     for file in item.iter("file"):
            #         for instance in file.iter("instance"):
            #             self.project['srcs'].append(instance.text.replace('\\', '/'))

        self.project['srcs'].append("../Arm/Packs/Keil/ARM_Compiler/1.6.3/Source/retarget_io.c")
        


        for element in self.root.Targets.Target.Groups.getchildren():
            print('GroupName: ' + element.GroupName.text)
            if hasattr(element, 'Files'):
                for file in element.Files.getchildren():
                    if not str(file.FilePath.text).endswith('.s'):
                        s = str(file.FilePath.text)
                        if os.path.sep not in s:
                            if os.path.sep == '\\':
                                s = s.replace('/', '\\')
                            elif os.path.sep == '/':
                                s = s.replace('\\', '/')
                        self.project['srcs'].append(s.replace('..', self.path, 1))
            # elif
        
        for i in range(0, len(self.project['incs'])):
            s = str(self.project['incs'][i])
            if os.path.sep not in s:
                if os.path.sep == '\\':
                    s = s.replace('/', '\\')
                elif os.path.sep == '/':
                    s = s.replace('\\', '/')

            self.project['incs'][i] = s.replace('..', self.path, 1)

        self.project['files'] = []
        i = 0

        # self.project['srcs'].append(RET_comp+"RTE_Device.h")
        # self.project['srcs'].append(RET_comp+"partition_IOTKit_CM33.h")
        self.project['srcs'].append(RET_comp+"system_IOTKit_CM33.c")

        # print(self.project['defs'])
        # print(self.project['srcs'])
        # self.project['files'].append(RET_comp+"startup_IOTKit_CM33.s")
        if os.path.exists(self.path + '/Drivers/CMSIS/Device/ST/STM32F3xx/Source/Templates/gcc'):
            for entry in os.listdir(self.path + '/Drivers/CMSIS/Device/ST/STM32F3xx/Source/Templates/gcc'):
                if entry.endswith('.S') or entry.endswith('.s'):
                    self.project['files'].append(self.path + '/Drivers/CMSIS/Device/ST/STM32F3xx/Source/Templates/gcc/'+ entry)

    def displaySummary(self):
        """ Display summary of parsed project settings
        """
        print('Project Name:' + self.project['name'])
        print('Project chip:' + self.project['chip'])
        print('Project includes: ' + ' '.join(self.project['incs']))
        print('Project defines: ' + ' '.join(self.project['defs']))
        print('Project srcs: ' + ' '.join(self.project['srcs']))
        print('Project: ' + self.project['mems'])

    def getProject(self):
        """ Return parsed project settings stored as dictionary
        @return Dictionary containing project settings
        """
        return self.project
