using Microsoft.AspNetCore.SignalR;
public class ChatHub(ChatHubService chatHubService) : Hub
{
    private readonly ChatHubService chatHubService = chatHubService;
    public async Task SendMessageToManager(string message)
    {
        (string userId, string staffId) = await chatHubService.GetUserByToken();
        string groupName = chatHubService.GetGroupName(staffId, userId);
        await Clients.Group(groupName).SendAsync("ReceiveMessage", userId, message);
    }
    public async Task JoinChat()
    {
        (string userId, string staffId) = await chatHubService.GetUserByToken();
        string groupName = chatHubService.GetGroupName(staffId, userId);

        await Groups.AddToGroupAsync(Context.ConnectionId, groupName);
    }
    public async Task ReplyToMemberMessage(string memberId, string message)
    {
        string? staffId = Context.UserIdentifier;
        string groupName = chatHubService.GetGroupName(staffId, memberId);
        await Clients.Group(groupName).SendAsync("ReceiveMessage", staffId, message);
    }
}
