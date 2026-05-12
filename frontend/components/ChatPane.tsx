import { useState, useEffect, useRef } from 'react';
import io, { Socket } from 'socket.io-client';

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

interface Session {
  session_id: string;
  mode: string;
}

export default function ChatPane() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [session, setSession] = useState<Session | null>(null);
  const [connected, setConnected] = useState(false);
  const [streaming, setStreaming] = useState(false);
  const messagesEnd = useRef<HTMLDivElement>(null);
  const socketRef = useRef<Socket | null>(null);

  useEffect(() => {
    const socket = io(process.env.NEXT_PUBLIC_WS_URL || 'http://localhost:8000', {
      transports: ['websocket'],
    });

    socket.on('connect', () => {
      setConnected(true);
      socket.emit('init', { session_id: null });
    });

    socket.on('session', (data: Session) => {
      setSession(data);
    });

    socket.on('message', (data: { chunk: string; done: boolean }) => {
      if (data.chunk) {
        setMessages(prev => {
          const last = prev[prev.length - 1];
          if (last && last.role === 'assistant') {
            return [...prev.slice(0, -1), { ...last, content: last.content + data.chunk }];
          }
          return [...prev, { role: 'assistant', content: data.chunk }];
        });
      }
      if (data.done) {
        setStreaming(false);
      }
    });

    socketRef.current = socket;

    return () => {
      socket.disconnect();
    };
  }, []);

  useEffect(() => {
    messagesEnd.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim()) return;

    const userMessage = { role: 'user' as const, content: input };
    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setStreaming(true);

    socketRef.current?.emit('chat', { message: input, mode: null });
  };

  return (
    <div className="chat-pane">
      <div className="messages">
        {messages.map((msg, i) => (
          <div key={i} className={`message ${msg.role}`}>
            {msg.content}
          </div>
        ))}
        <div ref={messagesEnd} />
      </div>

      <div className="input-area">
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSend()}
          placeholder={connected ? 'Describe your security task...' : 'Connecting...'}
          disabled={!connected || streaming}
        />
        <button onClick={handleSend} disabled={!connected || streaming}>
          Send
        </button>
      </div>

      <style jsx>{`
        .chat-pane {
          display: flex;
          flex-direction: column;
          height: 100%;
          background: #1a1a2e;
        }
        .messages {
          flex: 1;
          overflow-y: auto;
          padding: 20px;
        }
        .message {
          margin: 10px 0;
          padding: 12px 16px;
          border-radius: 8px;
          max-width: 80%;
        }
        .message.user {
          background: #4a4ae2;
          color: white;
          align-self: flex-end;
          margin-left: auto;
        }
        .message.assistant {
          background: #2d2d44;
          color: #e0e0e0;
        }
        .input-area {
          display: flex;
          gap: 10px;
          padding: 20px;
          border-top: 1px solid #333;
        }
        .input-area input {
          flex: 1;
          padding: 12px;
          border-radius: 8px;
          border: 1px solid #333;
          background: #2d2d44;
          color: white;
        }
        .input-area button {
          padding: 12px 24px;
          border-radius: 8px;
          background: #4a4ae2;
          color: white;
          border: none;
          cursor: pointer;
        }
        .input-area button:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }
      `}</style>
    </div>
  );
}