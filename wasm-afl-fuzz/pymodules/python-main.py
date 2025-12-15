#!/usr/bin/env python
# encoding: utf-8
'''
Example Python Module for AFLFuzz

@author:     Christian Holler (:decoder)

@license:

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

@contact:    choller@mozilla.com
'''

from __future__ import print_function, absolute_import, division, unicode_literals

from collections import namedtuple
from .wasm.modtypes import ModuleHeader, Section, SEC_UNK, SEC_NAME, NameSubSection
from .wasm.opcodes import OPCODE_MAP
from .wasm.compat import byte2int
from .wasm.types import *
from .mutator import *
from .weighted_choice import *
import random


# Wasm File Parser
def parser(buf):
    hdr = ModuleHeader()
    hdr_len, hdr_data, _ = hdr.from_raw(None, buf)
    buf = buf[hdr_len:]
    sec_list = []
    sec_data_list = []

    while buf:
        sec = Section()
        sec_len, sec_data, _ = sec.from_raw(None, buf)
        sec_list.append(sec)
        sec_data_list.append(sec_data)
        buf = buf[sec_len:]
    
    buf_new = hdr.rebuild(hdr_data)

    return buf_new, sec_list, sec_data_list


# mutation operations
def mutate(allField):
    byte_mutators = [mutate_case_0, mutate_case_1, mutate_case_2, mutate_case_3, mutate_case_4, mutate_case_5, mutate_case_6, 
                     mutate_case_7, mutate_case_8, mutate_case_9, mutate_case_10, mutate_case_11, mutate_case_12, mutate_case_13, 
                     mutate_case_14, mutate_case_15]
    structure_mutators = [mutate_case_structure_clone, mutate_case_structure_sub]
    structure_int_mutators = [muate_case_int_add, mutate_case_int_clone, mutate_case_int_sub]
    
    # Manually set the probability of different node types
    tuple_list = [('RepeatField', 2), ('BytesField', 6), ('UnsignedLeb128Field', 1), ('SignedLeb128Field', 1), ('UIntNField', 1)]

    # Randomly select the type of node that requires mutation. 
    # The higher the weight of the weight, the greater the probability of being selected (here you can redesign it)
    filedName = weighted_choice(tuple_list)
    
    # perform mutation
    if filedName == "BytesField":
        filed = allField.get(filedName)
        if len(filed) > 0:
            subnode = random.choice(filed)
            if subnode.name != "overhang" and len(subnode.data) > 0:
                bytemutate = random.choice(byte_mutators)
                _, fix_len = bytemutate(subnode.data)
                subnode.fix_node_data_length(fix_len)
                subnode.fix()

    if filedName == "RepeatField":
        filed = allField.get(filedName)
        if len(filed) > 0:
            subnode = random.choice(filed)
            if len(subnode.data) > 0:
                subnodeData = random.choice(subnode.data)
                if isinstance(subnodeData, StructureData):
                    structuremutate = random.choice(structure_mutators)
                    fix_len = structuremutate(subnode)
                    subnode.fix_node_data_length(fix_len)
                    subnode.fix()
                elif type(subnodeData) == int:
                    # handling data of int type
                    fix_len = 0
                    randomSelect = random.randint(1, 10)
                    if randomSelect >= 5:
                        structureintmutate = random.choice(structure_int_mutators)
                        fix_len = structureintmutate(subnode)
                    else:
                        if isinstance(subnode.type.field, SignedLeb128Field):
                            fix_len = mutate_case_signedint_replace(subnode)
                        elif isinstance(subnode.type.field, UnsignedLeb128Field):
                            fix_len = mutate_case_unsignedint_replace(subnode)
                        elif isinstance(subnode.type.field, UIntNField):
                            fix_len = mutate_case_uintn_replace(subnode)
                    subnode.fix_node_data_length(fix_len)
                    subnode.fix()
    
    # 这里加上后，有些虚拟机的测试时间长了会卡住，所以目前注释掉
    # 这几个Field在RepeatField会出现，上述已经实现相应的变异
    # if filedName == "UnsignedLeb128Field":
    #     filed = allField.get(filedName)
    #     if len(filed) > 0:
    #         subnode = random.choice(filed)
    #         fix_len = mutate_case_unsignedint_replace(subnode)
    #         subnode.fix_node_data_length(fix_len)
    #         subnode.fix()

    # if filedName == "SignedLeb128Field":
    #     filed = allField.get(filedName)
    #     if len(filed) > 0:
    #         subnode = random.choice(filed)
    #         fix_len = mutate_case_signedint_replace(subnode)
    #         subnode.fix_node_data_length(fix_len)
    #         subnode.fix()
    
    # if filedName == "UIntNField":
    #     filed = allField.get(filedName) 
    #     if len(filed) > 0:
    #         subnode = random.choice(filed)
    #         fix_len = mutate_case_uintn_replace(subnode)
    #         subnode.fix_node_data_length(fix_len)
    #         subnode.fix()


def init(seed):
    '''
    Called once when AFLFuzz starts up.

    @type seed: int
    @param seed: A 32-bit random value
    '''
    # generate a seed randomly
    random.seed(seed)
    return 0

def fuzz(buf, add_buf):
    '''
    Called per fuzzing iteration.
    
    @type buf: bytearray
    @param buf: The buffer that should be mutated.
    
    @type add_buf: bytearray
    @param add_buf: A second buffer that can be used as mutation source.
    
    @rtype: bytearray
    @return: A new bytearray containing the mutated data
    '''

    ret = bytearray(buf)
    
    # catch potential abnormal test cases or potential issues of parser
    try:
        ref_new, sec_list, sec_data_list = parser(ret)
    except Exception as e:
        print("Exception", e)
    
    # classify nodes according to the node types
    # interate every section from sec_list and perform mutation
    for i in range(len(sec_list)):
        nodes = sec_data_list[i].get_all_nodes()
         
        allField = []
        nodeUIntNField = []
        nodeUnsignedLeb128Field = []
        nodeSignedLeb128Field = []
        nodeCondField = []
        nodeRepeatField = []
        nodeConstField = []
        nodeBytesField = []

        for node in nodes:
            if isinstance(node.type, BytesField):
                nodeBytesField.append(node) 
            if isinstance(node.type, ConstField):
                nodeConstField.append(node)
            if isinstance(node.type, RepeatField) and not isinstance(node.type, BytesField):
                nodeRepeatField.append(node)
            if isinstance(node.type, CondField):
                nodeCondField.append(node)
            if isinstance(node.type, SignedLeb128Field):
                nodeSignedLeb128Field.append(node)
            if isinstance(node.type, UnsignedLeb128Field):
                nodeUnsignedLeb128Field.append(node)
            if isinstance(node.type, UIntNField):
                nodeUIntNField.append(node)
        
        allNodeField = [nodeBytesField, nodeRepeatField, nodeUnsignedLeb128Field, nodeSignedLeb128Field, nodeUIntNField]
        allFieldName = ['BytesField', 'RepeatField', 'UnsignedLeb128Field', 'SignedLeb128Field', 'UIntNField']
        allField = dict(zip(allFieldName, allNodeField))

        # mutation operation
        mutate(allField)

        ref_new += sec_list[i].rebuild(sec_data_list[i])

    return bytearray(ref_new)


def init_trim(buf):
    return 0

def trim():
    pass

def post_trim(success):
    return 0

# Uncomment and implement the following methods if you want to use a custom
# trimming algorithm. See also the documentation for a better API description.

# def init_trim(buf):
#     '''
#     Called per trimming iteration.
#     
#     @type buf: bytearray
#     @param buf: The buffer that should be trimmed.
#     
#     @rtype: int
#     @return: The maximum number of trimming steps.
#     '''
#     global ...
#     
#     # Initialize global variables
#     
#     # Figure out how many trimming steps are possible.
#     # If this is not possible for your trimming, you can
#     # return 1 instead and always return 0 in post_trim
#     # until you are done (then you return 1).
#         
#     return steps
# 
# def trim():
#     '''
#     Called per trimming iteration.
# 
#     @rtype: bytearray
#     @return: A new bytearray containing the trimmed data.
#     '''
#     global ...
#     
#     # Implement the actual trimming here
#     
#     return bytearray(...)
# 
# def post_trim(success):
#     '''
#     Called after each trimming operation.
#     
#     @type success: bool
#     @param success: Indicates if the last trim operation was successful.
#     
#     @rtype: int
#     @return: The next trim index (0 to max number of steps) where max
#              number of steps indicates the trimming is done.
#     '''
#     global ...
# 
#     if not success:
#         # Restore last known successful input, determine next index
#     else:
#         # Just determine the next index, based on what was successfully
#         # removed in the last step
#     
#     return next_index
