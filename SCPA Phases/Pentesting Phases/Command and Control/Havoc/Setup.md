# Setup

## 01 - Compile and Execute

### 1.1 - Arch-based distros

#### 1.1.1 - Install Dependencies

`$ sudo pacman -S git gcc base-devel cmake fontconfig glu gtest spdlog boost boost-libs ncurses gdbm openssl readline libffi sqlite bzip2 mesa qt5-base qt5-websockets python3 go nasm mingw-w64-gcc`

#### 1.1.2 - Clone the repository

`$ sudo git clone https://github.com/HavocFramework/Havoc.git /opt/post-exploitation/Havoc`

`$ sudo chown $USER:$(id -gn $USER) -R /opt/post-exploitation/Havoc`

#### 1.1.3 - Compile the client

`$ cd /opt/post-exploitation/Havoc/ && make client-build`

#### 1.1.4 - Compile the teamserver

```
$ cd /opt/post-exploitation/Havoc/teamserver && \
go mod download golang.org/x/sys && \
go mod download github.com/ugorji/go && \
cd .. && make ts-build
```

### 1.2 - Debian-based distros

#### 1.1.1 - Install Dependencies

`$ sudo apt install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev libspdlog-dev python3-dev libboost-all-dev mingw-w64 nasm`

#### 1.1.2 - Clone the repository

`$ sudo git clone https://github.com/HavocFramework/Havoc.git /opt/post-exploitation/Havoc`

`$ sudo chown $USER:$(id -gn $USER) -R /opt/post-exploitation/Havoc`

#### 1.1.3 - Compile the client

`$ cd /opt/post-exploitation/Havoc/ && make client-build`

#### 1.1.4 - Compile the teamserver

```
$ cd /opt/post-exploitation/Havoc/teamserver && \
go mod download golang.org/x/sys && \
go mod download github.com/ugorji/go && \
cd .. && make ts-build
```

## 02 - Teamserver and Client

### 2.1 - Setup Malleable C2 Profile

`$ cat profile-template.yaotl`

---

```
Teamserver {
    Host = "0.0.0.0"
    Port = 40056

    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "/usr/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Listeners {
    Http {
        Name        = "HTTPS Listener"
        Host        = "<IP>"
        Port        = <PORT>
        Method      = "POST"
        Secure      = true
        UserAgent   = "<User_Agent>"
        Uris        = [
            "/funny_cat.gif",
            "/index.php",
            "/test.txt",
            "/helloworld.js"
        ]
        Headers     = [
            "X-Havoc: true",
            "X-Havoc-Agent: Demon",
        ]

        Response {
            Headers = [
                "Content-type: text/plain",
                "X-IsHavocFramework: true",
                // "Content-type: text/html",
                // "Server: Apache",
                // "X-Powered-By: PHP/7.2.22",
            ]
        }

    }
}

Operators {
    user "redoperator" {
        Password = "mypass1234"
    }

    user "blackoperator" {
        Password = "pass1234"
    }
}

Service {
    // Endpoint = "service-endpoint"
    // Password = "service-password"
    Endpoint = "service-endpoint"
    Password = "<password>"
}

Demon {
    Sleep = 5
    Jitter = 15
    
    Implant {
        // Enables Sleep Mask obfuscation
        SleepMask = 1
        /*
         0 - WaitForSingleObjectEx (no obfuscation)
         1 - FOLIAGE
         2 - Ekko
        */
        SleepMaskTechnique = 0
    }

    Injection {
        Spawn64 = "C:\\Windows\\System32\\gpupdate.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\gpupdate.exe"
    }
}
```

* **Run the teamserver**

`$ cd /opt/post-exploitation/Havoc/`

`$ sudo ./havoc server --profile profiles/havoc.yaotl`

* **Run the client**

`$ cd /opt/post-exploitation/Havoc/`

`$ ./havoc client`

## 03 - Troubleshooting

Kali Linux and probably other pentest distros like Parrot may have a problem with the QT framework settings that has hardcoded font. It's an easy fix so here are the steps.

* Search **Qt5 Settings**

![[01 - Qt5 Settings.png]]

* Go to **Fonts** then change the **General** fonts

![[02 - Qt5 Fonts Configuration.png]]

* You're good to go user!