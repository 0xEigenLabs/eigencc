// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#ifndef MESSAGEMANAGER_H
#define MESSAGEMANAGER_H

#include <string>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>

#include "Worker.h"
#include "NetworkManagerClient.h"
#include "LogBase.h"
#include "Messages.pb.h"
#include "WebService.h"

using namespace std;

class MessageManager {

public:
    static MessageManager* getInstance();
    virtual ~MessageManager();
    int init(string path);
    vector<string> incomingHandler(string v, int type);
    void start();

private:
    MessageManager();
    string prepareVerificationRequest();
    string handleMSG0(Messages::MessageMsg0 m);
    string handleMSG1(Messages::MessageMSG1 msg);
    string handleMSG3(Messages::MessageMSG3 msg);
    string createInitMsg(int type, string msg);
    string handleAppAttOk(Messages::MessagePsiSalt msg);

    string handleHashData(Messages::MessagePsiResult msg, bool* finished);
    string handleHashIntersect(Messages::MessagePsiIntersect msg);

private:
    static MessageManager* instance;
    NetworkManagerClient *nm = NULL;
    PSIWorker *sp = NULL;
    WebService *ws = NULL;
};

#endif
