# wr30u_ssh

If you find any mistakes in this guide, _please_ submit a PR 👍🏻.

[forum.openwrt.org](https://forum.openwrt.org/t/openwrt-support-for-xiaomi-ax3000ne/153769)

## **Disclaimer:**

**You can potentially brick your device. I don't take responsibility for any damage caused.**

## Requirements

1. A Windows computer with an Ethernet adapter and a Wireless adapter.

2. An Ethernet cable.

3. Python 3.10 with `pycryptodome` 3.17 installed.

4. `server_emulator.py` from this repository.

## Enabling SSH Service

1. Configure the router.

   - Set port 1 as the WAN port.

     ![image-20230516190307397](img/image-20230516190307397.png)

   - Enable "启用与智能网关的无线配置同步".

     ![image-20230516190409582](img/image-20230516190409582.png)
     
   - Set the Internet connection type to "DHCP".

     ![image-20230516200033466](img/image-20230516200033466.png)

2. Connect your computer to a available wireless network and enable **Internet Connection Sharing** on the wireless network adapter's **Properties**. From the **Home networking connection** drop-down menu, select  **Your Ethernet Adapter**. This will set up a DHCP server on the Ethernet adapter and configure your computer as the gateway.

   ![image-20230516190718382](img/image-20230516190718382.png)

3. Connect the Ethernet port of your computer to **port 1** on the router. Now, the router should be able to obtain the following information and connect to the Internet.

   ![image-20230516200237559](img/image-20230516200237559.png)

4. Run server_emulator.py and wait for the router to found the connection.

   ```shell
   python.exe server_emulator.py
   ```

   ![image-20230516195137324](img/image-20230516195137324.png)

5. After waiting for about a minute, when the terminal outputs the router's information, it indicates a successful connection. Press any key to continue.

   ```shell
   # These commands will be executed
   echo -e 'admin\nadmin' | passwd root
   nvram set ssh_en=1 && nvram commit
   sed -i 's/channel=.*/channel="debug"/g' /etc/init.d/dropbear && /etc/init.d/dropbear start
   ```   
   ![image-20230516195354255](img/image-20230516195354255.png)

6. Close the Python program when it finishes.

   ![image-20230516195434825](img/image-20230516195434825.png)

7. Connect the Ethernet port of your computer to LAN port on the router.  Log in to the router using your favorite ssh client and account/password: `root/admin`.

   ![image-20230516195618159](img/image-20230516195618159.png)

8. fix ssh 

   ```mkdir /data/auto_ssh && cd /data/auto_ssh
curl -O https://cdn.jsdelivr.net/gh/lemoeo/AX6S@main/auto_ssh.sh
chmod +x auto_ssh.sh
uci set firewall.auto_ssh=include
uci set firewall.auto_ssh.type='script'
uci set firewall.auto_ssh.path='/data/auto_ssh/auto_ssh.sh'
uci set firewall.auto_ssh.enabled='1'
uci commit firewall
   ```   


