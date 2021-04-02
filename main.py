import pcapkit
import json
from scapy.all import *
from scipy.spatial import distance
import statistics
import dpkt
import tkinter as tk
from tkinter import filedialog, Text
import os
import pickle
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import VotingClassifier
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
from sklearn import model_selection

root = tk.Tk()
root.title("Cyber Attack Detector ")

fileName = ''
benignTag = 1

proposedFile = open('SPL3/SPL3/proposedpickle', 'rb')
proposedData = pickle.load(proposedFile)
proposedFile.close()






# proposedTrainingData = pd.read_csv('SPL3/SPL3/train_set_seed10_thres05.csv')
#
# proposed_label = proposedTrainingData['label_top']
# proposed_label = proposed_label.to_numpy()
#
# for i in range(0,len(proposed_label)):
#     if proposed_label[i]=='dos' or  proposed_label[i]=='r2l' or proposed_label[i]=='u2r' or proposed_label[i]=='probe':
#         proposed_label[i] ='attack'
#
# proposedTrainingData = proposedTrainingData.to_numpy()
# proposedTrainingData = proposedTrainingData[:,1:25]
# print(proposedTrainingData.shape)
#
# clf = RandomForestClassifier()
# clf.fit(proposedTrainingData, proposed_label)


def addFile():
    global json
    fileName = filedialog.askopenfilename(initialdir="/", title="select File",
                                          filetypes=(("executables", "*.pcap"), ("all files", "*.*")))
    filePath = fileName
    if fileName.find('benign') != -1 or fileName.find('normal') != -1:
        benignTag = 1
    else:
        benignTag = 0

    print(fileName)
    fileName = os.path.basename(fileName)
    fileName = fileName.split('.')[0]
    print(fileName)
    label = tk.Label(frame, text=filePath)
    label.pack()
    a = " "
    # fileName = 'in'
    f = open(fileName + ".txt", "a")

    data = filePath
    a = rdpcap(data)
    sessions = a.sessions()
    for session in sessions:
        f.write(session + '\n')
        print(session)
    #
    # print(len(sessions))
    f.close()

    jsonData = pcapkit.extract(fin=filePath, fout=fileName + '.json', format='json', extension=False)
    with open(fileName + '.json') as json_file:
        data = json.load(json_file)

    for item in data:
        print(item)

    # print(len(data))

    import json

    jsonFile = open(fileName + '.json', 'r')
    jsonData = jsonFile.read()
    obj = json.loads(jsonData)

    #

    protocol_name = ''
    protocol_value = -1
    protocol_TTl = -1
    src_ip = ''
    dst_ip = ''
    src_port = -1
    dst_port = -1
    seq = -1
    ack = -1
    window_size = -1

    forwordConnectData = []
    backworkConnectData = []
    flowData = []
    flowNumber = 1
    actualSRCIp = src_ip
    actualDSTIp = dst_ip
    flagList = []

    forwardTimeList = []
    backwardTimeList = []
    overallTimeList = []

    forwardLengthList = []
    backwardLengthList = []
    overallLengthList = []

    CICIDS_features = [
        'Destination Port',
        'Total Length of Bwd Packets',
        'Bwd Packet Length Mean',
        'Idle Max',
        'Flow IAT Mean',
        'Bwd Header Length',
        'Min Packet Length',
        'Down/Up Ratio',
        'Subflow Bwd Bytes',
        'Init_Win_bytes_forward',
        'Init_Win_bytes_backward',
        'Idle Std',
        'Flow Bytes/s'
    ]

    for i in range(2, len(data)):
        # print('')
        # print('time :' + str(obj['Frame ' + str(i)]['time_epoch']))
        time = obj['Frame ' + str(i)]['time_epoch']

        # print('len :' + str(obj['Frame ' + str(i)]['len']))
        packetLen = obj['Frame ' + str(i)]['len']

        # print('header length :' + str(len(obj['Frame ' + str(i)]['ethernet']['packet']['header']['hex']) / 2))
        header_len = len(obj['Frame ' + str(i)]['ethernet']['packet']['header']['hex']) / 2

        forwardTag = 1

        if obj['Frame ' + str(i)]['ethernet']['type']['name'] == "Internet_Protocol_version_4":
            # print('protocol name : ' + obj['Frame ' + str(i)]['ethernet']['ipv4']['proto']['name'])
            # print('protocol value : ' + str(obj['Frame ' + str(i)]['ethernet']['ipv4']['proto']['value']))
            # print('protocol TTL : ' + str(obj['Frame ' + str(i)]['ethernet']['ipv4']['ttl']))
            # print('src ip :' + obj['Frame ' + str(i)]['ethernet']['ipv4']['src'])
            # print('dst ip :' + obj['Frame ' + str(i)]['ethernet']['ipv4']['dst'])
            protocol_name = obj['Frame ' + str(i)]['ethernet']['ipv4']['proto']['name']
            protocol_value = obj['Frame ' + str(i)]['ethernet']['ipv4']['proto']['value']
            protocol_TTl = obj['Frame ' + str(i)]['ethernet']['ipv4']['ttl']
            src_ip = obj['Frame ' + str(i)]['ethernet']['ipv4']['src']
            dst_ip = obj['Frame ' + str(i)]['ethernet']['ipv4']['dst']

            if obj['Frame ' + str(i)]['ethernet']['ipv4']['proto']['name'] == 'TCP':
                # print('srcport : ' + str(obj['Frame ' + str(i)]['ethernet']['ipv4']['tcp']['srcport']))
                # print('dstport :' + str(obj['Frame ' + str(i)]['ethernet']['ipv4']['tcp']['dstport']))
                # print('seq : ' + str(obj['Frame ' + str(i)]['ethernet']['ipv4']['tcp']['seq']))
                # print('ack : ' + str(obj['Frame ' + str(i)]['ethernet']['ipv4']['tcp']['ack']))
                src_port = obj['Frame ' + str(i)]['ethernet']['ipv4']['tcp']['srcport']
                dst_port = obj['Frame ' + str(i)]['ethernet']['ipv4']['tcp']['dstport']
                window_size = obj['Frame ' + str(i)]['ethernet']['ipv4']['tcp']['window_size']
                seq = obj['Frame ' + str(i)]['ethernet']['ipv4']['tcp']['seq']
                ack = obj['Frame ' + str(i)]['ethernet']['ipv4']['tcp']['ack']
                flagDic = obj['Frame ' + str(i)]['ethernet']['ipv4']['tcp']['flags']
                for flag in flagDic:
                    if flagDic[flag] == True:
                        flagList.append(flag)

            elif obj['Frame ' + str(i)]['ethernet']['ipv4']['proto']['name'] == 'UDP':
                # print('srcport: ' + str(obj['Frame ' + str(i)]['ethernet']['ipv4']['udp']['srcport']))
                # print('dstport : ' + str(obj['Frame ' + str(i)]['ethernet']['ipv4']['udp']['dstport']))
                src_port = obj['Frame ' + str(i)]['ethernet']['ipv4']['udp']['srcport']
                dst_port = obj['Frame ' + str(i)]['ethernet']['ipv4']['udp']['dstport']

        if actualSRCIp == '' and actualDSTIp == '':
            actualDSTIp = dst_ip
            actualSRCIp = src_ip
        elif actualSRCIp == src_ip and actualDSTIp == dst_ip:
            forwardTag = 1
        elif actualSRCIp == dst_ip and actualDSTIp == src_ip:
            forwardTag = 0
        else:
            forwardTag = -1
            actualSRCIp = src_ip
            actualDSTIp = dst_ip

        eachPacketData = {
            "time": time,
            "packetLen": packetLen,
            "header_len": header_len,
            "protocol_name": protocol_name,
            "protocol_value": protocol_value,
            "protocol_TTl": protocol_TTl,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "seq": seq,
            "ack": ack,
            'flags': flagList,
            'window_size': window_size
        }
        flagList = []
        if forwardTag == 1:
            forwordConnectData.append(eachPacketData)
            forwardTimeList.append(time)
            forwardLengthList.append(packetLen)
            overallTimeList.append(time)
            overallLengthList.append(packetLen)
        elif forwardTag == 0:
            backworkConnectData.append(eachPacketData)
            backwardTimeList.append(time)
            backwardLengthList.append(packetLen)
            overallTimeList.append(time)
            overallLengthList.append(packetLen)
        elif forwardTag == -1:
            eachFlowData = {
                "forwardConnectData": forwordConnectData,
                "backwardConnectData": backworkConnectData,
                "flowNumber": flowNumber,
                'forwardTimeList': forwardTimeList,
                'backwardTimeList': backwardTimeList,
                'forwardLenthList': forwardLengthList,
                'backwardLenthList': backwardLengthList,
                'totalTimeList': overallTimeList,
                'totalLenthList': overallLengthList
            }
            forwordConnectData = []
            backworkConnectData = []
            overallTimeList = []
            overallLengthList = []
            backwardLengthList = []
            forwardLengthList = []
            flowData.append(eachFlowData)
            flowNumber += 1
            forwordConnectData.append(eachPacketData)
            forwardTimeList.append(time)
            forwardLengthList.append(packetLen)
            overallLengthList.append(packetLen)
            overallTimeList.append(time)

        if i == (len(data) - 1):
            eachFlow = {
                'forwardConnectData': forwordConnectData,
                'backwardConnectData': backworkConnectData,
                'flowNumber': flowNumber,
                'forwardTimeList': forwardTimeList,
                'backwardTimeList': backwardTimeList,
                'forwardLenthList': forwardLengthList,
                'backwardLenthList': backwardLengthList,
                'totalTimeList': overallTimeList,
                'totalLenthList': overallLengthList
            }
            forwordConnectData = []
            backworkConnectData = []
            overallTimeList = []
            flowData.append(eachFlow)

    # for i in range(len(flowData)):
    #     print('forward')
    #     print(flowData[i].get("forwardConnectData"))
    #     print('backward')
    #     print(flowData[i].get("backwardConnectData"))

    # print(len(sessions))
    # print(len(flowData))

    ###################################### feature extract ##########

    for i in range(0, len(flowData)):
        destination_port = flowData[i].get("forwardConnectData")[0]['dst_port']
        backwardLengthListofPkt = flowData[i].get("backwardLenthList")
        total_length_backward_packet = 0
        backward_len_mean = 0
        init_backward_window = 0
        init_forward_window = 0
        for val in range(0, len(backwardLengthListofPkt)):
            total_length_backward_packet += backwardLengthListofPkt[val]
        if len(backwardLengthListofPkt) > 0:
            backward_len_mean = total_length_backward_packet / len(backwardLengthListofPkt)

        IAT_mean = 0
        totalTimeList = flowData[i].get("totalTimeList")
        for index in range(1, len(totalTimeList)):
            IAT_mean += (totalTimeList[index] - totalTimeList[index - 1])
        if len(totalTimeList):
            IAT_mean = (IAT_mean / (len(totalTimeList))) * (10) * (10) * (10)

        backwardPktData = flowData[i].get("backwardConnectData")
        backwardHeaderLenth = 0
        for index in range(0, len(backwardPktData)):
            backwardHeaderLenth += flowData[i].get("backwardConnectData")[index]['header_len']
        min_pkt_len = min(flowData[i].get("totalLenthList"))
        down_vs_up = len(flowData[i].get("backwardLenthList")) / len(flowData[i].get("forwardLenthList"))

        if len(flowData[i].get("forwardConnectData")) > 0:
            init_forward_window = flowData[i].get("forwardConnectData")[0]['window_size']
        if len(flowData[i].get("backwardConnectData")) > 0:
            init_backward_window = flowData[i].get("backwardConnectData")[0]['window_size']

        init_forward_window_bytes = 0
        init_backward_window_bytes = 0

        for index in range(0, len(backwardPktData)):
            if flowData[i].get("backwardConnectData")[index]['window_size'] == init_backward_window:
                init_backward_window_bytes += flowData[i].get("backwardConnectData")[index]['packetLen']
        forwardPktData = flowData[i].get("forwardConnectData")

        for index in range(0, len(forwardPktData)):
            if flowData[i].get("forwardConnectData")[index]['window_size'] == init_forward_window:
                init_forward_window_bytes += flowData[i].get("forwardConnectData")[index]['packetLen']

        flowBytes = sum(flowData[i].get("totalLenthList"))

        current_src_ip = flowData[i].get("forwardConnectData")[0]['src_ip']
        current_dst_ip = flowData[i].get("forwardConnectData")[0]['dst_ip']
        IDLE_statelist = []
        ActiveStateList = []

        currentFlowtimelist = flowData[i].get("totalTimeList")
        currentFlowtimelist.sort()

        for index in range(i + 1, len(flowData)):
            if flowData[index].get("forwardConnectData")[0]['src_ip'] == current_src_ip and \
                    flowData[index].get("forwardConnectData")[0]['dst_ip'] == current_dst_ip:
                lastPacketTimeofCurrentFlow = currentFlowtimelist[0]
                traverseFlowtimelist = flowData[index].get("totalTimeList")
                traverseFlowtimelist.sort()
                IDLE_time = traverseFlowtimelist[0] - lastPacketTimeofCurrentFlow
                IDLE_statelist.append(IDLE_time)
                currentTotalTime = flowData[i].get("totalTimeList")
                if len(currentTotalTime) > 0: ActiveStateList.append(max(currentTotalTime) - min(currentFlowtimelist))
                if len(traverseFlowtimelist) > 0: ActiveStateList.append(
                    max(traverseFlowtimelist) - min(traverseFlowtimelist))

        IDLE_Max, IDLE_std, IDLEMin, IDLEMean = 0.0, 0.0, 0.0, 0.0
        Active_Max, Active_Min, Active_Mean, Active_Std = 0.0, 0.0, 0.0, 0.0

        if len(IDLE_statelist) > 0:
            IDLE_Max = max(IDLE_statelist)
            if len(IDLE_statelist) > 1: IDLE_std = statistics.stdev(IDLE_statelist)
            IDLEMin = min(IDLE_statelist)
            IDLEMax = max(IDLE_statelist)
            IDLEMean = statistics.mean(IDLE_statelist)

        if len(ActiveStateList) > 0:
            Active_Max = max(ActiveStateList)
            if len(ActiveStateList) > 1: Active_Std = statistics.stdev(ActiveStateList)
            Active_Min = min(ActiveStateList)
            Active_Mean = statistics.mean(ActiveStateList)

        FlowDuration = 0
        if len(currentFlowtimelist):
            FlowDuration = (max(currentFlowtimelist) - min(currentFlowtimelist)) * 1000000

        print(destination_port, total_length_backward_packet, backward_len_mean, IAT_mean, IDLE_Max,
              backwardHeaderLenth, min_pkt_len,
              down_vs_up, init_forward_window_bytes, init_backward_window_bytes, IDLE_std, flowBytes)

        # ######################################### Irrelavent Features################

        # totalForwardPackets
        forwardPktData = flowData[i].get("forwardConnectData")
        totalForwardPackets = len(forwardPktData)
        forwardPacketLenList = []
        totalLenthofFwdPkt = 0
        minLenthofFwdPkt = 0
        maxLenthofFwdPkt = 0
        meanLenthofFwdPkt = 0
        stdLenthofFwdPkt = 0
        if totalForwardPackets > 0:
            for index in range(0, totalForwardPackets):
                forwardPacketLenList.append(forwardPktData[index]['packetLen'])
            totalLenthofFwdPkt = sum(forwardPacketLenList)
            minLenthofFwdPkt = min(forwardPacketLenList)
            maxLenthofFwdPkt = max(forwardPacketLenList)
            meanLenthofFwdPkt = forwardPktData[0]['packetLen']
            stdLenthofFwdPkt = 0
            if totalForwardPackets > 1:
                meanLenthofFwdPkt = statistics.mean(forwardPacketLenList)
                stdLenthofFwdPkt = statistics.stdev(forwardPacketLenList)

        # totalForwardPackets
        backwardPktData = flowData[i].get("backwardConnectData")
        totalbackwardPackets = len(backwardPktData)
        backwardPacketLenList = []
        totalLenthofbackPkt = 0
        minLenthofbackPkt = 0
        maxLenthofbackPkt = 0
        meanLenthofbackPkt = 0
        stdLenthofbackPkt = 0
        if totalbackwardPackets > 0:
            for index in range(0, totalbackwardPackets):
                backwardPacketLenList.append(backwardPktData[index]['packetLen'])
            totalLenthofbackPkt = sum(backwardPacketLenList)
            minLenthofbackPkt = min(backwardPacketLenList)
            maxLenthofbackPkt = max(backwardPacketLenList)
            meanLenthofbackPkt = forwardPktData[0]['packetLen']
            stdLenthofbackPkt = 0
            if totalForwardPackets > 1:
                meanLenthofbackPkt = statistics.mean(forwardPacketLenList)
                stdLenthofbackPkt = statistics.stdev(forwardPacketLenList)

        flowbytesPersec = 0
        flowPktsPerSec = 0

        if max(currentFlowtimelist) - min(currentFlowtimelist) > 0:
            flowbytesPersec = (
                    sum(flowData[i].get("totalLenthList")) / ((max(currentFlowtimelist) - min(currentFlowtimelist))))
            flowPktsPerSec = (totalForwardPackets + totalbackwardPackets) / (
                (max(currentFlowtimelist) - min(currentFlowtimelist)))

        ########## IAT measure ######
        totalIAT = []

        for index in range(1, len(currentFlowtimelist)):
            totalIAT.append((currentFlowtimelist[index] - currentFlowtimelist[index - 1]) * 1000000)

        forwardIAT = []
        currentforwardTimeList = flowData[i].get("forwardTimeList")
        for index in range(1, len(currentforwardTimeList)):
            forwardIAT.append((currentforwardTimeList[index] - currentforwardTimeList[index - 1]) * 1000000)

        backwardIAT = []
        currentbackwardTimeList = flowData[i].get("backwardTimeList")

        if len(currentbackwardTimeList) > 1:
            for index in range(1, len(currentbackwardTimeList)):
                backwardIAT.append((currentbackwardTimeList[index] - currentbackwardTimeList[index - 1]) * 1000000)

        if len(totalIAT) > 0:
            totalIATMin = min(totalIAT)
            totalIATMax = max(totalIAT)
            totalIATStd = 0
            if len(totalIAT) > 1:
                totalIATStd = statistics.stdev(totalIAT)

        if len(forwardIAT) > 0:
            forwardIATStd = 0
            forwardIATMin = min(forwardIAT)
            forwardIATMax = max(forwardIAT)
            forwardIATMean = statistics.mean(forwardIAT)
            if len(forwardIAT) > 1: forwardIATStd = statistics.stdev(forwardIAT)
            forwardIATotal = sum(forwardIAT)

        if len(backwardIAT) > 0:
            backwardIATMin = min(backwardIAT)
            backwardIATMax = max(backwardIAT)
            backwardIATMean = statistics.mean(backwardIAT)
            if len(backwardIAT) > 1: backwardIATStd = statistics.stdev(backwardIAT)
            backwardIATTotal = sum(backwardIAT)
        else:
            backwardIATMin = 0
            backwardIATMax = 0
            backwardIATMean = 0
            backwardIATStd = 0
            backwardIATTotal = 0

        fwdPushFlagCount = 0
        fwdURGFlagCount = 0
        backwardUrgFlagCount = 0
        backwardPushFlagCount = 0
        forwardCWRFlagCount = 0
        backwardCWRFlagCount = 0
        forwardECEFlagCount = 0
        backwardECEFlagCount = 0
        forwardACKFlagCount = 0
        backwardACKFlagCount = 0
        forwardRSTFlagCount = 0
        backwardRSTFlagCount = 0
        forwardSYNFlagCount = 0
        backwardSYNFlagCount = 0
        forwardFINFlagCount = 0
        backwardFINFlagCount = 0

        for index in range(0, len(forwardPktData)):
            flags = forwardPktData[index]['flags']
            for flagIndex in range(0, len(flags)):
                if flags[flagIndex] == 'psh':
                    fwdPushFlagCount += 1
                if flags[flagIndex] == 'urg':
                    fwdURGFlagCount += 1
                if flags[flagIndex] == 'cwr':
                    forwardCWRFlagCount += 1
                if flags[flagIndex] == 'ece':
                    forwardECEFlagCount += 1
                if flags[flagIndex] == 'rst':
                    forwardRSTFlagCount += 1
                if flags[flagIndex] == 'syn':
                    forwardSYNFlagCount += 1
                if flags[flagIndex] == 'fin':
                    forwardFINFlagCount += 1
                if flags[flagIndex] == 'ack':
                    forwardACKFlagCount += 1

        for index in range(0, len(backwardPktData)):
            flags = backwardPktData[index]['flags']
            for flagIndex in range(0, len(flags)):
                if flags[flagIndex] == 'psh':
                    backwardPushFlagCount += 1
                if flags[flagIndex] == 'urg':
                    backwardUrgFlagCount += 1
                if flags[flagIndex] == 'cwr':
                    backwardCWRFlagCount += 1
                if flags[flagIndex] == 'ece':
                    backwardECEFlagCount += 1
                if flags[flagIndex] == 'rst':
                    backwardRSTFlagCount += 1
                if flags[flagIndex] == 'syn':
                    backwardSYNFlagCount += 1
                if flags[flagIndex] == 'fin':
                    backwardFINFlagCount += 1
                if flags[flagIndex] == 'ack':
                    backwardACKFlagCount += 1

        totalPSHFlag = fwdPushFlagCount + backwardPushFlagCount
        totalUrg = fwdURGFlagCount + backwardUrgFlagCount
        totalCwr = forwardCWRFlagCount + backwardCWRFlagCount
        totalEce = forwardECEFlagCount + backwardECEFlagCount
        totalRst = forwardRSTFlagCount + backwardRSTFlagCount
        totalSyn = forwardSYNFlagCount + backwardSYNFlagCount
        totalFin = forwardFINFlagCount + backwardFINFlagCount
        totalAck = forwardACKFlagCount + backwardACKFlagCount

        fwdHeaderLenth = 0
        bwdHeaderLenth = 0
        for index in range(0, len(forwardPktData)):
            fwdHeaderLenth += forwardPktData[index]['header_len']

        for index in range(0, len(backwardPktData)):
            bwdHeaderLenth += backwardPktData[index]['header_len']

        fwdPacketsPersec = 0
        backpacketspersec = 0
        if (max(currentFlowtimelist) - min(currentFlowtimelist)) > 0:
            fwdPacketsPersec = (totalForwardPackets) / (max(currentFlowtimelist) - min(currentFlowtimelist))
            backpacketspersec = (totalbackwardPackets) / (max(currentFlowtimelist) - min(currentFlowtimelist))

        packetLenthData = flowData[i].get("totalLenthList")
        minPacketLen = min(packetLenthData)
        maxPacketLen = max(packetLenthData)
        meanPacketLen = statistics.mean(packetLenthData)
        stdDevPacketLen, variancePacketLen = 0, 0
        if len(packetLenthData) > 1:
            stdDevPacketLen = statistics.stdev(packetLenthData)
            variancePacketLen = statistics.variance(packetLenthData)

        print(FlowDuration, totalLenthofFwdPkt, minLenthofFwdPkt, maxLenthofFwdPkt, meanLenthofFwdPkt, stdLenthofFwdPkt,
              totalLenthofbackPkt, minLenthofbackPkt, maxLenthofbackPkt, meanLenthofbackPkt, stdLenthofbackPkt,
              flowbytesPersec, flowPktsPerSec, backwardIATMin, backwardIATMax, backwardIATMean, backwardIATStd,
              backwardIATTotal,
              fwdPushFlagCount, backwardPushFlagCount, fwdURGFlagCount, backwardUrgFlagCount, fwdHeaderLenth,
              bwdHeaderLenth,
              fwdPacketsPersec, backpacketspersec, minPacketLen, maxPacketLen, meanPacketLen, stdDevPacketLen,
              variancePacketLen,
              totalAck, totalCwr, totalEce, totalFin, totalSyn, totalRst, totalPSHFlag,
              Active_Min, Active_Mean, Active_Max, Active_Std,
              IDLEMin, IDLEMean, IDLE_Max, IDLE_std)

    def test_predict(test_feature, train_corr_mean, cov_corr, md_mean, md_std_dev, alpha):
        left_bound = md_mean - (alpha * md_std_dev)
        right_bound = md_mean + (alpha * md_std_dev)
        mahalanobis_dist = np.zeros(test_feature.shape[0])
        pred_val = np.zeros(test_feature.shape[0])
        # print(mahalanobis_dist.shape)
        for i in range(mahalanobis_dist.shape[0]):
            left = test_feature[i] - train_corr_mean
            left = np.array([left])
            right = np.transpose(left)
            left = np.matmul(left, cov_corr)
            right = np.matmul(left, right)
            mahalanobis_dist[i] = np.sqrt(np.absolute(np.squeeze(right)))
            if mahalanobis_dist[i] > left_bound and mahalanobis_dist[i] < right_bound:
                pred_val[i] = 0
            else:
                pred_val[i] = 1
        return pred_val

    def accuracy(pred_val, target_val):
        number_of_sample = pred_val.shape[0]
        number_of_target = np.count_nonzero(pred_val == target_val)
        rate = number_of_target / number_of_sample
        return rate

    infile = open('SPL3/SPL3/abcpickle', 'rb')
    new_dict = pickle.load(infile)
    infile.close()

    kdd_attack = new_dict['kdd_attack']
    kdd_normal = new_dict['kdd_normal']

    normal_index = np.arange(len(kdd_normal) - 1)
    attack_index = np.arange(len(kdd_attack) - 1)
    np.random.shuffle(normal_index)
    np.random.shuffle(attack_index)
    # print(normal_index, attack_index)

    dataForPrediction = []
    normalDataCount = 0
    attackDataCount = 0

    if benignTag:
        normalDataCount = int(len(flowData) * 0.70)
        attackDataCount = len(flowData) - normalDataCount
    else:
        attackDataCount = int(len(flowData) * 0.70)
        normalDataCount = len(flowData) - attackDataCount

    for i in range(0, attackDataCount):
        dataForPrediction.append(kdd_attack[attack_index[i]])
    for i in range(0, normalDataCount):
        dataForPrediction.append(kdd_normal[normal_index[i]])

    dataForPrediction = np.array(dataForPrediction)

    no_of_corr_feat = int(dataForPrediction.shape[1] * (dataForPrediction.shape[1] - 1) / 2)
    data_test_normal = np.zeros((dataForPrediction.shape[0], no_of_corr_feat))
    # print(kdd_attack.shape)
    # print(data_test_normal.shape)
    f = int(0)
    for i in range(0, dataForPrediction.shape[1]):
        for j in range(i + 1, dataForPrediction.shape[1]):
            data_test_normal[:, f] = dataForPrediction[:, i] + dataForPrediction[:, j]
            f = f + 1

    predicted_label = test_predict(data_test_normal, new_dict['train_corr_mean'], new_dict['cov_corr'],
                                   new_dict['md_mu'], new_dict['md_std'], alpha=1)
    abcAccu = accuracy(predicted_label, 0)
    # print(accuracy(predicted_label, 0))

    corrcorrFile = open('SPL3/SPL3/corrcorrpickle', 'rb')
    corrData = pickle.load(corrcorrFile)
    corrcorrFile.close()

    corrcorr_normal = corrData['normal_data_model']
    # predicted_label = test_predict(corrcorr_normal, corrData['train_corr_mean'], corrData['cov_corr'], corrData['md_mu'],
    #                                corrData['md_std'], alpha=1)
    # print(accuracy(predicted_label, 0))

    corrcorr_attack = corrData['attack_data_model']
    # predicted_label = test_predict(corrcorr_attack, corrData['train_corr_mean'], corrData['cov_corr'], corrData['md_mu'],
    #                                corrData['md_std'], alpha=1)
    # print(accuracy(predicted_label, 1))

    # print(len(corrcorr_normal))
    normal_index = np.arange(len(corrcorr_normal) - 1)
    attack_index = np.arange(len(corrcorr_attack) - 1)
    np.random.shuffle(normal_index)
    np.random.shuffle(attack_index)
    # print(normal_index, attack_index)

    dataForPrediction = []
    for i in range(0, normalDataCount):
        dataForPrediction.append(corrcorr_normal[normal_index[i]])
    for i in range(0, attackDataCount):
        dataForPrediction.append(corrcorr_attack[attack_index[i]])

    dataForPrediction = np.array(dataForPrediction)
    predicted_label = test_predict(dataForPrediction, corrData['train_corr_mean'], corrData['cov_corr'],
                                   corrData['md_mu'],
                                   corrData['md_std'], alpha=1)

    acu = accuracy(predicted_label, 0)
    # print(accuracy(predicted_label, 0))
    # print(normalDataCount, attackDataCount, benignTag)

    ensembleFile = open('SPL3/SPL3/ensemblepickle', 'rb')
    ensembleData = pickle.load(ensembleFile)
    ensembleTrainData = ensembleData['data'].to_numpy()
    ensembleFile.close()
    # print(ensembleTrainData)
    normalData = ensembleData['normalData']
    attackData = ensembleData['attackData']
    label = ensembleData['label']
    dataForPrediction = []
    for i in range(0, normalDataCount):
        dataForPrediction.append(normalData[normal_index[i]])
    for i in range(0, attackDataCount):
        dataForPrediction.append(attackData[attack_index[i]])

    estimators = []
    model2 = DecisionTreeClassifier()
    estimators.append(('cart', model2))
    model3 = RandomForestClassifier(n_estimators=20)
    estimators.append(('randomforest', model3))
    ensemble = VotingClassifier(estimators, voting='soft')
    ensemble.fit(ensembleTrainData, label)

    predicted = ensemble.predict(np.array(dataForPrediction))
    count = int(0)
    for i in range(0, len(predicted)):
        if ('BENIGN' == predicted[i]):
            count += 1

    benignAccu = count / len(predicted)
    # print()
    # print(predicted)
    proposedKddAttackData = proposedData['kdd_attack_proposed']
    proposedKddNormalData = proposedData['kdd_normal_proposed']
    proposedKddAttackData = proposedKddAttackData.to_numpy()
    proposedKddNormalData = proposedKddNormalData.to_numpy()
    print(proposedKddNormalData.shape)

    clf = pickle.load(open('SPL3/SPL3/proposedModel', 'rb'))

    dataForPrediction = []
    for i in range(0, normalDataCount):
        dataForPrediction.append(proposedKddNormalData[normal_index[i]])
    for i in range(0, attackDataCount):
        dataForPrediction.append(proposedKddAttackData[attack_index[i]])

    proposedKddNormalData = proposedKddNormalData[:, 0:41]
    proposedKddAttackData = proposedKddAttackData[:, 0:41]
    dataForPrediction = np.array(dataForPrediction)

    train_array_mean = np.mean(proposedKddNormalData, axis=0)
    print(train_array_mean.shape)
    print(dataForPrediction.shape)

    train_array_std = np.zeros(proposedKddNormalData.shape[1])
    for i in range(0, proposedKddNormalData.shape[1]):
        val = np.std(proposedKddNormalData[:, i])
        if val == 0:
            train_array_std[i] = 1
        else:
            train_array_std[i] = val

    #train_array = dataForPrediction
    train_array = dataForPrediction[:, 0:41]
    train_label = dataForPrediction[:, 41]
    for i in range(0, len(train_label)):
        if train_label[i] == 'dos' or train_label[i] == 'r2l' or train_label[i] == 'u2r' or train_label[i] == 'probe':
            train_label[i] = 'attack'

    no_of_groups = 24
    columns_of_new_train_set = []
    for i in range(0, no_of_groups):
        columns_of_new_train_set.append("Group-" + str(i))

    print(columns_of_new_train_set)
    store_by_group = np.zeros((train_array.shape[0], no_of_groups))
    print(store_by_group.shape)

    proposedGroupPickleData = pickle.load(open('SPL3/SPL3/proposedGroupPickle', 'rb'))
    members_in_group = proposedGroupPickleData['members_in_group']
    adj_mat = proposedGroupPickleData['adj_mat']

    for i in range(0, no_of_groups):
        mem = int(members_in_group[i])
        # print("Group=",i,"Member=",mem)
        group_mean = np.zeros(mem)
        group_std = np.zeros(mem)
        temp_train = np.zeros((train_array.shape[0], mem))
        temp_train_top = np.zeros((proposedKddNormalData.shape[0], mem))
        cov_train = np.zeros((proposedKddNormalData.shape[1], proposedKddNormalData.shape[1]))
        # print("Group Mean=",group_mean.shape,"Temp Train",temp_train.shape,"Temp Train Top",temp_train_top.shape,"Cov Train",cov_train.shape)
        for j in range(0, mem):
            neigh_ind = int(adj_mat[i][j])
            # print("Group:",i,"Mem=",neigh_ind)
            group_mean[j] = train_array_mean[neigh_ind]
            group_std[j] = train_array_std[neigh_ind]
            temp_train[:, j] = train_array[:, neigh_ind]
            temp_train_top[:, j] = proposedKddNormalData[:, neigh_ind]
        if mem > 1:
            temp_train_top = np.transpose(temp_train_top)
            cov_train = np.cov(temp_train_top)
            cov_train = np.linalg.inv(cov_train)

        if mem == 1:
            for k in range(0, train_array.shape[0]):
                dist = distance.euclidean(temp_train[k], group_mean)
                store_by_group[k][i] = dist / group_std[0]

        else:
            for k in range(0, train_array.shape[0]):
                dist = distance.mahalanobis(temp_train[k], group_mean, cov_train)
                store_by_group[k][i] = dist

    proposedPrediction = clf.predict(store_by_group)
    count=0
    for index in range(0,len(proposedPrediction)):
        if proposedPrediction[index]=='normal':
            count+=1

    proposedAccu = float(count/len(proposedPrediction))

    print(proposedPrediction)
    label = tk.Label(frame, text="ABC    Benign Percentage: " + str(abcAccu * 100) + "       Attack Percentage  " + str(
        (1 - abcAccu) * 100))
    label.pack()

    label = tk.Label(frame,
                     text="CorrCorr    Benign Percentage: " + str(acu * 100) + "       Attack Percentage  " + str(
                         (1 - acu) * 100))
    label.pack()
    label = tk.Label(frame,
                     text="Ensemble    Benign Percentage: " + str(
                         benignAccu * 100) + "       Attack Percentage  " + str(
                         (1 - benignAccu) * 100))
    label.pack()
    label = tk.Label(frame,
                     text="Proposed Method    Benign Percentage: " + str(
                         proposedAccu * 100) + "       Attack Percentage  " + str(
                         (1 - proposedAccu) * 100))
    label.pack()


canvas = tk.Canvas(root, height=900, width=900, bg="#253F45")
canvas.pack()
frame = tk.Frame(root, bg="white")
frame.place(relwidth=0.85, relheight=0.85, relx=0.095, rely=0.095)
openFile = tk.Button(root, text='Open File', padx=20, pady=10, fg="white", bg="#234D45", command=addFile)
openFile.pack()
root.mainloop()
#addFile('D:/pycharm/pcapAnalyzer/attackPcap/2016-12-30-Sundown-EK-1st-run-sends-Terdot.A-Zloader.pcap')
