import asyncio
import websockets
import json
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv('./config.env')

# Load configuration from .env
AGENT_VERSION = os.getenv("AGENT_VERSION")
RETRIES = int(os.getenv("RETRIES", 3))  # Default to 3 retries if not set
SERVER_ID = os.getenv("SERVER_ID")
REVERB_URI = os.getenv("REVERB_URI")
REVERB_CHANNEL = os.getenv("REVERB_CHANNEL")


class WebSocketClient:
    _instance = None  # Class-level variable to hold the singleton instance
    _websocket = None  # The WebSocket connection will be stored here

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(WebSocketClient, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'initialized'):  # Ensure initialization only happens once
            self.initialized = True
            self.retries = 0
            self.websocket = None  # WebSocket will be established once
            self._loop = asyncio.get_event_loop()

    async def _connect(self):
        while self.retries < RETRIES or RETRIES == 0:
            try:
                self.websocket = await websockets.connect(REVERB_URI)
                print("Connected to Laravel Reverb!")
                break
            except websockets.exceptions.ConnectionClosedError:
                print("Connection closed by the server. Retrying...")
                self.retries += 1
                await asyncio.sleep(2)  # Wait 2 seconds before retrying
            except Exception as e:
                print(f"An error occurred: {e}")
                self.retries += 1
                await asyncio.sleep(2)  # Wait 2 seconds before retrying

        if self.retries >= RETRIES:
            print("Max retries reached. Could not connect to the WebSocket server.")
            self.websocket = None
        
        return self

    async def send(self, action, data):
        if self.websocket is None:
            # Connect if not already connected
            await self._connect()

        if self.websocket:
            try:
                # Prepare the message
                message = {
                    "event": 'agent.'+action,
                    "channel": REVERB_CHANNEL,
                    "server_id":SERVER_ID,
                    "agent_version": AGENT_VERSION,
                    "action": action,
                    "data": data,
                }

                # Send the message as JSON
                await self.websocket.send(json.dumps(message))
                print(f"Sent data: {message}")
            except Exception as e:
                print(f"Failed to send data: {e}")
        else:
            print("WebSocket is not connected. Could not send data.")

    async def close(self):
        if self.websocket:
            await self.websocket.close()
            print("WebSocket connection closed.")
