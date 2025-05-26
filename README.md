# Windows Keylogger

This project is a basic keylogger PoC for Windows that can be installed as a system service. It records keystrokes and sends logs through a Telegram bot.

## Features

- Records all pressed keys
- Runs as a Windows service (invisible to the user)
- Encrypts locally saved logs
- Sends logs via Telegram
- Protects log files with hidden attributes and restrictive permissions
- Stealth mode to avoid detection
- Automatic process priority adjustment

## Configuration

Before compiling, you need to configure the Telegram bot:

1. Create a Telegram bot using [BotFather](https://t.me/botfather)
2. Get your bot token
3. Find the chat ID where logs will be sent
4. Modify the following lines in the `keylogger.cpp` file:
   ```cpp
   #define TELEGRAM_BOT_TOKEN "YOUR_TOKEN_HERE"
   #define TELEGRAM_CHAT_ID "YOUR_CHAT_ID_HERE"
   ```

## Compilation

1. Open the project in Visual Studio
2. Make sure required libraries are linked (winhttp.lib, advapi32.lib, crypt32.lib, wininet.lib, psapi.lib)
3. Compile in Release mode for x64 architecture

```
cl /EHsc /O2 /W4 /std:c++17 /MT keylogger.cpp /link winhttp.lib advapi32.lib crypt32.lib wininet.lib psapi.lib
```

## Usage

The program can be run in different modes:

### Console mode (testing)
```
keylogger.exe console
```

### Install as Windows service
```
keylogger.exe install
```

### Uninstall service
```
keylogger.exe uninstall
```

## Security Notes

The keylogger stores logs in a hidden location on the system and uses techniques to make its detection difficult. Log files are encrypted using a key defined in the code.

The author assumes no liability for misuse of this software or any damage that may result from its use. 
