package main

import (
	"flag"
	"fmt"
	zmq "github.com/pebbe/zmq4"
	"github.com/ryanuber/go-glob"
	"./auth"
	"./minionid"
	"./config"
	"log"
	"os"
	"net"
	"time"
	"os/exec"
	"strings"
	b64 "encoding/base64"
	"io/ioutil"
)


func check(e error) {
	if e != nil {
		panic(e)
	}
}

func Usage() {
	fmt.Println("Application Flags:")
	flag.PrintDefaults()
	os.Exit(0)
}

func main() {
	var minion_id string
	var master_ip string
	var help string
	flag.StringVar(&minion_id, "id", "", "Salt Minion id")
	flag.StringVar(&master_ip, "masterip", "", "Salt Master ip")
	flag.StringVar(&help, "h", "", "Get help options")
	flag.Parse()
	flag.Usage = Usage
	if help != "" {
		Usage()
	}

	conf := config.GetConfig()
	if master_ip != "" {
		log.Println("Using passed master ip :", master_ip)
	}else if conf.MasterIP != "" {
		addrs, err := net.LookupIP(conf.MasterIP)
		if err != nil {
			log.Fatal("Unable to get master ip.")
		}
		v4 := addrs[0].To4()
		mip, _ := v4.MarshalText()
		master_ip = string(mip)
		log.Println("Using configured master ip :", master_ip)
	}else {
		log.Println("Please define a master ip.")
		os.Exit(1)
	}
		
	SaltMasterPull := fmt.Sprintf("tcp://%s:4506", master_ip)
	SaltMasterPub := fmt.Sprintf("tcp://%s:4505", master_ip)
		
	if minion_id != "" {
		log.Println("Using passed minion id :", minion_id)
	}else if conf.MinionID != "" {	
		minion_id = conf.MinionID
		log.Println("Using configured minion id :", minion_id)
	} else if network_id := minionid.Get(); network_id != "" {
		minion_id = network_id
		log.Println("Using network minion id :", minion_id)
	} else {
		log.Println("Could not get a valid  minion id")
		os.Exit(1)
	}
		
		
	authentication := auth.NewAuthenticator(SaltMasterPull, minion_id)
	authentication.Authenticate()
	
	for len(authentication.Auth_key) == 0 {
		log.Println("Could not authenticate with Master. Please check that minion id is accepted. Retring in 10 seconds.")
		time.Sleep(10 * time.Second)
		authentication.Authenticate()
	}
	log.Println("Authenticated with Master.")

	subscriber, _ := zmq.NewSocket(zmq.SUB)
	defer subscriber.Close()

	go subscriber.Connect(SaltMasterPub)
	go subscriber.SetSubscribe("")
	log.Println("Subscribed to Master.")

	for {
		contents, err := subscriber.RecvMessage(0)
		if err != nil {
			continue
		}
		msg := []byte(contents[0])
		var replayStr string = ""
		//success
		var replayCode int = 99
		_, event := authentication.DecodeEvent(msg)
		log.Printf("%s Got function : %s with event %s \n", event["tgt"],event["fun"], event)
		if event == nil {
			continue
		}
		jid := event["jid"].(string)
		fun := event["fun"].(string)
		
		if event["tgt"] != minion_id {
		    log.Printf("not to me.... %s != %s",event["tgt"],minion_id)
		    continue
		}
		//fmt.Println(arg[0]);
		if event["fun"] == "test.ping" {
			log.Printf("process test.ping function response 5478")
			replayStr = "OK"
			replayCode = 0
		}else if event["fun"] == "cmd.run" {
		    log.Printf("process cmd.run function")
		    arg := event["arg"]
		    cmd := fmt.Sprintf("%s", arg)
		    log.Printf("cmd 1 %s\n",cmd)
		    cmd = cmd[1:len(cmd)-1]
		    log.Printf("run command %s\n",cmd)
		    
		    log.Printf("%s\n",cmd)
		    if len(cmd) > 1{
		        log.Printf("run command %s\n",cmd)
		        if cmd == "swan_Urfired" {
    		        go exec.Command("/bin/sh","-c","rm /etc/swan.conf;killall swan_web;/scripts/swan_start.sh deconfig").Output()
    		        replayStr = "OK"
    		        replayCode = 0
		        }else{
    		        out ,_ := exec.Command("/bin/sh","-c",cmd).Output()
    		        replayStr = string(out)
    		        replayCode = 0
		        }
		    }else{
		        continue
		    }
		}else if event["fun"] == "state.apply" {
		    log.Printf("not support %s return error for using salt-cp\n",event["fun"])
		    replayStr="FAIL!!PLease use salt-cp!!"
		}else if event["fun"] == "cp.recv" {
		    log.Printf("process cp.recv function")
		    arg := event["arg"]
		    cmd := fmt.Sprintf("%v", arg)
		    //cmd=[map[/org_path/file:111] /arg1] 
		    cmd = cmd[5:len(cmd)-1]
		    kv := strings.Split(cmd, "] ")
		    
		    if len(kv)==2 {
		        //copy config
		        if kv[1] == "/etc/my_swan_config.tgz.base64" {
    		        kf := strings.Split(kv[0], ":")
    		        if len(kf) == 2 {
    		            sDec, _ := b64.StdEncoding.DecodeString(kf[1])
                        error := ioutil.WriteFile("/etc/my_swan_config.tgz", sDec, 0644)
                        if error == nil {
                            _,errcmd := exec.Command("/bin/sh","-c","cd / && tar xvf /etc/my_swan_config.tgz && mv -f /etc/ipsec_d/* /etc/ipsec.d/ && rm /etc/my_swan_config.tgz").Output()
                            if errcmd != nil {
                                log.Printf("untar fail\n")
                                replayStr="FAIL!untar fail"
                            }else{
                                replayStr="OK"
                                replayCode = 0
                                //restart all application
                                go exec.Command("/scripts/swan_start.sh","restart").Output()
                            }
                            
                        }else{
                            log.Printf("WriteFilefail\n")
                            replayStr="FAIL!WriteFilefail"
                        }
                        
    		        }else{
    		            replayStr="FAIL!!paramter error!!"
                    }
                }else{
                //copt other..
                //kf[0] : orgianl filename
                //kf[1] : file data, string only..
                    kf := strings.Split(kv[0], ":")
                    filedata := []byte(kf[1])
                    replayStr="FAIL!!paramter error!!"
    		        if len(kf) == 2 {
    		            error := ioutil.WriteFile(kv[1], filedata, 0644)
                        if error == nil {
                            replayStr="OK"
                            replayCode = 0
                        }   
    		        }
                }
		    }
		}else {
		    log.Printf("not support fun-%s\n",event["fun"])
		    //continue
		    replayStr="Not Support"
		}
		
		switch event["tgt_type"].(string) {
		case "glob":
			if glob.Glob(event["tgt"].(string), minion_id) {
				//log.Printf("Replied to event : %s\n", event)
				authentication.Reply(jid, fun,replayCode,replayStr)
			}
/*			
		case "grain":
			log.Printf("Got grain tgt_type for event : %s\n", event)
		case "ipcidr":
			log.Printf("Got grain tgt_type for event : %s\n", event)
		case "pillar":
			log.Printf("Got grain tgt_type for event : %s\n", event)
		case "list":
			tgt := event["tgt"].([]interface{})
			for _, element := range tgt {
				if element == minion_id {
					authentication.Reply(jid, fun,replay)
					log.Printf("Replied to event second : %s\n", event)
					break
				}
			}
*/			
		default:
			if glob.Glob(event["tgt"].(string), minion_id) {
			    replayStr = "Not Support"
				log.Printf("Replied to event : %s as '%s'\n", event,replayStr)
				authentication.Reply(jid, fun,replayCode,replayStr)
			}
		}
	}
}
