using CloudinaryDotNet;
using Microsoft.AspNetCore.Http;
using MilkStore.Contract.Services.Interface;
using CloudinaryDotNet.Actions;
using Microsoft.Extensions.Configuration;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
namespace MilkStore.Services.Service
{
    public class CloudinaryService : ICloudinaryService
    {
        private readonly Cloudinary _cloudinary;
        public CloudinaryService(IConfiguration configuration)
        {
            var cloudinaryConfig = configuration.GetSection("Cloudinary");
            var account = new Account(
                cloudinaryConfig["CloudName"],
                cloudinaryConfig["ApiKey"],
                cloudinaryConfig["ApiSecret"]
            );
            _cloudinary = new Cloudinary(account);
        }
        public async Task<string> UploadImageAsync(IFormFile file)
        {
            if (file.Length == 0) throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! File empty"); 

            // Chuyển đổi IFormFile sang một MemoryStream để upload lên Cloudinary
            using var stream = file.OpenReadStream();
            var uploadParams = new ImageUploadParams()
            {
                File = new FileDescription(file.FileName, stream),
                Transformation = new Transformation().Quality(80).Crop("limit") // Có thể tuỳ chỉnh transformation
            };
            var uploadResult = await _cloudinary.UploadAsync(uploadParams);

            return uploadResult.SecureUrl.AbsoluteUri;
        }
        public async Task DeleteImageAsync(string publicId)
        {
            var deletionParams = new DeletionParams(publicId);
            var result = _cloudinary.Destroy(deletionParams); // Gọi phương thức Delete (Destroy)

            if (result.Result != "ok")
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Can't delete");
            }
        }
    }
}
