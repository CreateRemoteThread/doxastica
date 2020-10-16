listener = ls_bind(8080);

server = ls_accept(listener);
client = ls_connect("192.168.242.5",8080)

bCont = 1
while (bCont == 1) 

do
  d_server = ls_recv(server,1024) 
  if(d_server== -1) then
    bCont = 0
  end
  if(d_server ~= nil) then
    print("Server Msg")
    print(d_server)
    ls_send(client,d_server)
  end
  d_client = ls_recv(client,1024)
  if(d_client == -1) then
    
    bCont = 0
  end
  if(d_client ~= nil) then
    print("Client Msg")
    print(d_client)
    ls_send(server,d_client)
  end
end

ls_closesocket(server);
ls_closesocket(client);
print("Done!");