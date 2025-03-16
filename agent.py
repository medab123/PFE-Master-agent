from resource.resource_monitoring import ResourceMonitoring
from resource.trafic_monitoring import TrafficMonitoring
from resource.user_activity_monitoring import UserActivityMonitoring
import socket
import time
from multiprocessing import Process
import sqlite3
from dotenv import load_dotenv
import os
import asyncio

from services.reverb import WebSocketClient



sleep_time = 3
sync_sleep_time = 3


def subscribe_agent(client, db_connection):
    cursor = db_connection.cursor()

    cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subscribed INTEGER DEFAULT 0
            )
        ''')
    
    cursor.execute('SELECT subscribed FROM settings WHERE id = 1')
    result = cursor.fetchone()
    
    if result is None:
        cursor.execute('INSERT INTO settings (subscribed) VALUES (0)')
        db_connection.commit()
        result = (0,)
    
    if result[0] == 0:
        print("Not subscribed. Sending subscription event.")
        
        client.send("subscribe", {})
        cursor.execute('UPDATE settings SET subscribed = 1 WHERE id = 1')
        db_connection.commit()
        print("Subscription successful. Database updated.")
    else:
        print("Already subscribed. No action needed.")


    
async def main():
    db_path = 'database.db' 
    client = await WebSocketClient()._connect()
    if client.websocket is None:
        raise Exception("Failed to connect to the WebSocket server")
    
    db_connection = sqlite3.connect(db_path)
    subscribe_agent(client=client, db_connection=db_connection)
    db_connection.close()
    await asyncio.gather(
        ResourceMonitoring().start(client=client, sleep_time=1, batch_size=1),
        TrafficMonitoring().start(client=client, sleep_time=1, batch_size=1),
        #UserActivityMonitoring().start(client=client, sleep_time=1, batch_size=1)
    )



if __name__ == "__main__":

    asyncio.run(main())