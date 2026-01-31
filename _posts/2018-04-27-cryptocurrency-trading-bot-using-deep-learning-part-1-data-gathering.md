---
title: "Cryptocurrency Trading Bot Using Deep Learning: Part-1 Data Gathering"
date: 2018-04-27
categories: 
  - "data-science"
  - "deep-learning"
  - "general-programming"
tags: 
  - "algorithm-trading"
  - "automatic-trading-bot"
  - "binance-api"
  - "cryptocurrency"
  - "data-science"
  - "deeptraderbot"
  - "python-binance"
---

Recently, cryptocurrency trading has been one of the most talked topics of the technology. With severe ups and downs, bitcoin and cryptocurrency trading gets attention from millions of investors. Its unpredictable nature and volatility attracted my attention. So I decided to develop an **automated cryptocurrency bot using deep learning**. The bot should be able to analyze the current trends and changes in the price and should decide when and how much it will buy or sell to make profits.

There will be several posts to break the bot into manageable parts. So this time, instead of a one script project, it will be a big project with Object-Oriented Design and several files. It would be very difficult to share all the code in one post, so **if you are interested and want to run the code, you can get it from here: [https://github.com/yusuftas/deep\_trader\_bot](https://github.com/yusuftas/deep_trader_bot)** .

This first post will cover the part of data gathering. Since I am planning to use Deep Learning, it will need lots of data samples to make good predictions. It is possible to get historical data without all this code, but I am planning to run real time tests to see if the bot can make a profit, all this code posted here will definitely be needed.

<!--more-->

**1\. Registering on Binance and Creating an API key**

Nowadays, there are many cryptocurrency exchanges available online and more are opening each day. I already had an account in Binance, so I decided to use Binance throughout this post series. Binance was easy to use and easy to register such as no need to send photos etc. I don't know if that changed since I haven't used it for a long time. If you want to register you can use this link :

[https://www.binance.com/?ref=15603967](https://www.binance.com/?ref=15603967)

It has my referral code by the way, if you wonder what that number is :)

After getting the account ready, now it is time to create an API key. API stands for Application Programming Interface. It helps us, developers, to get access to website's functionality to create programs by using their interface and supplied functions. In this case, we will be using Binance's API to connect to the account, check prices etc.

Firstly you should start by creating a new API Key. To create the API key, from this page: [https://www.binance.com/userCenter/createApi.html](https://www.binance.com/userCenter/createApi.html) you need to enter a label for your key :

![](/assets/img/key_create.jpg)

After that, you will probably get a confirmation mail to your email address, you need to confirm this within 30 minutes or so. After confirming, your key should be created and you should get something similar to this:

![](/assets/img/api_key.jpg)

This two strings are very important, especially the second one. Second one is your private key and **will only be shown once, so make sure you saved it to a safe place**. These keys are similar to the keys to your house, so don't share them with anyone else. I already deleted the shown keys above, so don't try to access my account :)

**2\. Accessing Binance using the API**

Binance gives us a REST API to use. Details of the API can be found in the documentation : [https://github.com/binance-exchange/binance-official-api-docs/blob/master/rest-api.md](https://github.com/binance-exchange/binance-official-api-docs/blob/master/rest-api.md)

REST API simply means that you can use the API by sending HTTP POST/PUT/DELETE requests. In this requests, you can give the relevant information and get back the result using the HTTP. Although it is simple to use, preparing and receiving HTTP requests can be quite bothersome. So I decided to prepare a wrapper in Python to make it much easier to send and receive requests. But luckily it was already done by someone else which I am quite happy about it. Open source for the win :)

I used [python-binance wrapper written by Sam Mchardy](https://github.com/sammchardy/python-binance). It was exactly what I needed. He has quite a few other API wrappers for other exchanges. If you want to use a different exchange than Binance, there might be already a wrapper ready.

To install the wrapper you can download the source from github and install or you can directly install it using pip. I believe, you also need to install twisted. If twisted is not installed, pip will try to compile it and if your C++ compiler is not setup correctly, you might face problems. In that case, if you are using conda, you can install twisted from conda _"conda install twisted"_, then you can run the pip command, hopefully without a problem:

`pip install python-binance`

After that if it is installed correctly you should be able to import it without any problems. You can use your generated keys to connect to the API. **You should change the keys to your own API access keys** :

```python
from binance.client import Client

api_key    = 'your_api_key'
api_secter = 'your_api_secret_key'

client = Client(api_key, api_secret)
```

If everything has worked, you should now have access to Binance API in python, congratulations :)

**3\. Representation of Data and Candles**

Now that we have the connection, it is time to talk about **Data**. There are many different representation of the data available when we talk about any exchange in general. Candlestick charts is one of them, and if you have used exchanges many of them use candlestick charts. Advantage of candlestick charts is that you can easily check opening,closing prices and trends in one graph. If you would like to learn more about candles, you can check the [wikipedia article](https://en.wikipedia.org/wiki/Candlestick_chart).

Since I am using an object-oriented design, I decided to create a separate class to hold candlestick information :

```python
class CandleBase:

    symbol    = ""

    starttime = 0
    stoptime  = 0
    openp  = 0
    closep = 0
    highp  = 0
    lowp   = 0

    def __init__(self, starttime, stoptime,openp,closep,highp,lowp):
        self.starttime = starttime
        self.stoptime = stoptime
        self.openp = openp
        self.closep = closep
        self.highp = highp
        self.lowp = lowp

def __str__(self):

        out_str = "%d to %d //  %.8f  %.8f  %.8f  %.8f " %(self.starttime,self.stoptime,self.openp,self.closep,self.highp,self.lowp)
        return out_str
```

It is a straightforward class. By creating an instance of CandleBase, I wanted to hold opening, closing, high and low prices of a time frame which is represented by start and stop time for that candle. My general aim is to create candles throughout some session, for example 1 minute candles over 2 hours recording session. This would maybe show us the trends in short terms and might be helpful in day-trading.

**4\. Data Fetching and Saving**

Now, we need to get the data from Binance. There are several ways to do that. I will be using the Websocket streams of the API, more details here : [https://github.com/binance-exchange/binance-official-api-docs/blob/master/web-socket-streams.md](https://github.com/binance-exchange/binance-official-api-docs/blob/master/web-socket-streams.md)

If you look at the documentation, there is a part **Kline/Candlesticks**. It pushes updates to the websocket for the given interval candles. And there are many different intervals available which is quite nice to have from minute to 1 month.

Websocket streams are fairly easy to use in python-binance wrapper as well. Let me first show you the full Bot class first :

```python
from binance.client import Client
from binance.enums import *
from binance.websockets import BinanceSocketManager
from collections import deque
from twisted.internet import reactor
from CandleBase import CandleBase
import pickle
#import cPickle as pickle  #for python 2.x

class DeepTraderBotv1:

    symbol  = ""
    balance = 0		           # in terms of btc
    totalStoredCandles = 0
    lastStoredCandles= 0
    maxcandles = 200    
    
    def __init__(self, config,maxcandles = 50):
        self.symbol = config['symbol']
        self.maxcandles = maxcandles 
        self.candleQueue = deque(maxlen=self.maxcandles)

    def setKeyPriv(self,config):
        self.key  = config['key']
        self.priv = config['priv']

    def connectClientAccount(self,key = None , priv = None):

        if key == None and priv == None:
            self.client = Client(self.key , self.priv)
        else:	    
            self.client = Client(key , priv)

    def closeConnection(self):
        try:
            self.bm.stop_socket(self.conn_key)
            self.bm.close()
            reactor.stop()
        except:
            print('Problem stopping connections')    
        
    def connectWebSocket(self):
        self.bm       = BinanceSocketManager(self.client)
        self.conn_key = self.bm.start_kline_socket(self.symbol, self.process_message_kline, interval=KLINE_INTERVAL_1MINUTE)
        self.bm.start()

    def saveCandles(self,fname):
        fileObject = open(fname,'wb')
        pickle.dump(self.candleQueue,fileObject)
        fileObject.close()     
   
        #clear the queue
        self.candleQueue.clear()
        print('Saved the queue and cleared it.')

    def loadCandles(self,fname):
        fileObject = open(fname,'rb')
        self.candleQueue = pickle.load(fileObject)
        fileObject.close()
        
    def getTotalStored(self):
        return self.totalStoredCandles

    def process_message_kline(self,msg):
        kline   = msg['k']
        openp  = float(kline['o'])
        closep = float(kline['c'])
        highp  = float(kline['h'])
        lowp   = float(kline['l'])

        starttime = kline['t']
        stoptime  = kline['T']

        if kline['x'] == True:		#kline is it closed ?

            candle = CandleBase(starttime, stoptime,openp,closep,highp,lowp)
            
            self.candleQueue.append(candle)
            self.totalStoredCandles = self.totalStoredCandles + 1
            
            if self.totalStoredCandles%self.maxcandles == 0:                
                fname = self.symbol + '_' + str(self.lastStoredCandles) + '_' + str(self.totalStoredCandles) 
                self.saveCandles(fname)
                
                self.lastStoredCandles = self.totalStoredCandles

```

Now let's go over the important points.

1. **Line 3 :** to use the websockets in python-binance, you will need to import it first, obviously.
2. **connectClientAccount:** This method expects API key as parameters. And with the given API keys it starts a connection to Binance API. This part is important because you will need to initialize Client, before connecting to a websocket
3. **Line 43,44,45:** After you get Client connected, you can start a websocket connection. Kline(candlestick) socket is the one we are using here. First parameter is symbol such as 'BNBBTC', 'ETHBTC' etc. This symbol are also used in Binance, it shows the market of exchanging from one currency to the other currency. Second parameter is the fallback method, it will be called when new data arrives from the socket. And the last parameter is interval, you can check other intervals from the documentation link above. I am using 1 minute intervals since I am planning to do a short time trends analysis.
4. **Line 65:** process\_message\_kline: In this method you can do whatever you are planning with the new data from websocket. For this post, since we are saving data, we will create an instance of Candle and queue it. Later on when we come to the data analysis related posts, we will use the new coming data to predict future movements and decide to invest or hold. Currently it checks if the current kline is the final kline for the given interval. If it is so, than we can use this kline and update our queue with the new data. For now, when stored candles reach a given amount, I use **pickle to save them to the disk**. In the next post, I will load all the saved candles and do some plotting etc. as an initial analysis step.

Rest is classic methods for utility, saving,loading etc. Now let's move on to the main function.

**5\. Main script**

Main script is where I use my bot. Currently bot has only data saving functionality, so main script is limited to that, but I will be extending the code as we progress and add more functionality:

```python
import sys
import os
import time
from DeepTraderBot import DeepTraderBotv1
from bot_utils import read_configuration

if __name__ == "__main__":
    #Read the configuration file
    config = read_configuration('settings.config')

    #set credential of the accounts.    
    mybot = DeepTraderBotv1(config,maxcandles=5)
    mybot.setKeyPriv(config)
    
    #Depending on the running type start an operation
    runner = config['running_type']
    
    if runner == 'save':
        mybot.connectClientAccount()
        mybot.connectWebSocket()
    elif runner == 'test':
        print('Testing some part of the code')
    #more options will be added
    else:                           
        sys.exit('Error: Unknown running type is given')
   
    #Program execution options    	
    
    while 1:
        selection = input("Your selection? (h for help) ")    #python 3.x, for 2.x use raw_input
        
        if len(selection) > 1:
            print('Enter one character only.')
        elif selection == 'h':
            print('Select only one character option from available list:')
            print('\n\t h : help')
            print('\n\t e : exit')
            print('\n\t p : print total stored candles')
        elif selection == 'e':
            print('Exiting the program and stopping all processes.')
            mybot.closeConnection()
            raise Exception('exit')
        elif selection == 'p':
            print('Total candles: ' + str(mybot.getTotalStored()))
        else:
            print('Unknown option.')    
        

```

Now let's go over few important points:

1. **Line 9:** Bot will be initialized by the help of a configuration file. As of now, contents of the configuration file is very simple :
    
    ```python
    [DEFAULT]
    key = yourkey
    priv = yoursecretkey
    symbol = ETHBTC
    running_type = save
    ```
    
    You need to change key and secret key to your own API keys.
    
2. **Line 16:** Running type of the bot will be loaded from configuration file. Currently, bot is only able to save data :)
3. **Line 29 to 45:** Main control loop of the robot. Few options available, help, exit and so on. Exiting was causing some problems and not closing the websocket properly. To fix that, I used twisted's **reactor.stop()** method to completely close websocket which is inside the bot's class. P option is to print information about stored candles. Webscoket connection is a background process and fallback method is triggered when new data arrives, so you don't really see much of what is happening. I put this method to check current total stored candles to make sure everything is working fine.

This has been a long post already. You can find the full source code here : [https://github.com/yusuftas/deep\_trader\_bot](https://github.com/yusuftas/deep_trader_bot). More posts and extensions to the bot will be coming soon. See you in another post, and as always keep learning.
