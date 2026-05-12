export default function Home() {
  return (
    <div className="container">
      <ChatPane />
      <LivePanel />

      <style jsx>{`
        .container {
          display: grid;
          grid-template-columns: 40% 60%;
          height: 100vh;
          background: #0f0f1a;
        }
      `}</style>
    </div>
  );
}