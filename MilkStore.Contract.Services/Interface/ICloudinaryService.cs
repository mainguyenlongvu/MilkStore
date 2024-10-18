using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
namespace MilkStore.Contract.Services.Interface
{
    public interface ICloudinaryService
    {
        Task<string> UploadImageAsync(IFormFile file);
        Task DeleteImageAsync(string publicId);
    }
}
