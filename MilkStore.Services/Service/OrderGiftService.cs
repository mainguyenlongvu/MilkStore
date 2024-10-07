using AutoMapper;
using MailKit;
using Microsoft.AspNetCore.Http;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.ModelViews.GiftModelViews;
using MilkStore.ModelViews.OrderGiftModelViews;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.Repositories.Context;
using MilkStore.Repositories.Entity;
using MilkStore.Services.EmailSettings;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using OrderGiftStatus = MilkStore.Contract.Repositories.Entity.OrderGiftStatus;
namespace MilkStore.Services.Service
{
    public class OrderGiftService : IOrderGiftService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly DatabaseContext context;
        private readonly IMapper _mapper;
        private readonly IEmailService _emailService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public OrderGiftService(DatabaseContext context, IUnitOfWork unitOfWork, IMapper mapper, IEmailService mailService, IHttpContextAccessor httpContextAccessor)
        {
            this.context = context;
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _emailService = mailService;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task CreateOrderGift(OrderGiftModel orderGiftModel)
        {
            string? userID = _httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrWhiteSpace(userID))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Please log in first!");
            }
            OrderGift newOG = _mapper.Map<OrderGift>(orderGiftModel);
            newOG.CreatedTime = DateTime.UtcNow;
            newOG.UserID = Guid.Parse(userID);
            newOG.Status = OrderGiftStatus.Pending;
            await _unitOfWork.GetRepository<OrderGift>().InsertAsync(newOG);
            await _unitOfWork.SaveAsync();
        }

        public async Task DeleteOrderGift(string id)
        {
            if (String.IsNullOrWhiteSpace(id))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Input wrong id");
            }
            OrderGift OrderGift1 = await _unitOfWork.GetRepository<OrderGift>().GetByIdAsync(id);

            if (OrderGift1.DeletedTime != null)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, $"Doesn't exist:{id}");
            }
            OrderGift1.DeletedTime = DateTime.UtcNow;
            await _unitOfWork.GetRepository<OrderGift>().UpdateAsync(OrderGift1);
            await _unitOfWork.SaveAsync();
        }

        public async Task<IEnumerable<OrderGiftResponseDTO>> GetOrderGift(string? id)
        {
            if (id == null)
            {
                // Lấy tất cả sản phẩm
                IEnumerable<OrderGift> OGift = await _unitOfWork.GetRepository<OrderGift>().GetAllAsync();

                // Lọc sản phẩm có DeleteTime == null
                OGift = OGift.Where(p => p.DeletedTime == null);

                return _mapper.Map<IEnumerable<OrderGiftResponseDTO>>(OGift);
            }
            else
            {
                // Lấy sản phẩm theo ID
                OrderGift OGift = await _unitOfWork.GetRepository<OrderGift>().GetByIdAsync(id) ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! OrderGift null");

                if (OGift.DeletedTime == null) // Kiểm tra DeleteTime
                {
                    return new List<OrderGiftResponseDTO> { _mapper.Map<OrderGiftResponseDTO>(OGift) };
                }
                else
                {
                    return new List<OrderGiftResponseDTO>();
                }
            }
        }


        public async Task UpdateOrderGift(string id, OrderGiftModel orderGiftModel, OrderGiftStatus ordergiftstatus)
        {
            string? userID = _httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrWhiteSpace(userID))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Please log in first!");
            }
            if (string.IsNullOrWhiteSpace(id))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Input wrong id");
            }
            DateTime currentDate = DateTime.Now;
            DateTime futureDate = currentDate.AddDays(3);
            DateTime futureDate2 = currentDate.AddDays(5);
            string temp = "Thời gian giao dự kiến từ " + futureDate.ToString("dd/MM/yyyy") + " đến " + futureDate2.ToString("dd/MM/yyyy");
            string productname = ""; // lấy thông tin theo id
            
            int dem = 0;
            OrderGift newOG = _mapper.Map<OrderGift>(orderGiftModel);
            newOG.UserID = Guid.Parse(userID);
            newOG.Status = ordergiftstatus;
            ApplicationUser user = await _unitOfWork.GetRepository<ApplicationUser>().GetByIdAsync(newOG.UserID)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! User null");
            IEnumerable<OrderDetailGift> ODG = await _unitOfWork.GetRepository<OrderDetailGift>().GetAllAsync();
            foreach (var item in ODG)
            {

                if (item.OrderGiftId == id)
                {
                    Gift gift = await _unitOfWork.GetRepository<Gift>().GetByIdAsync(item.GiftId);
                    dem += gift.point * item.quantity;
                    productname += " " + gift.Products.ProductName + " Số lượng: " + item.quantity;
                }
            }
            string temp1 = " Quà tặng gồm: " + productname;
            if (newOG.Status == OrderGiftStatus.Confirmed)
            {
                _emailService.SendEmailAsync(user.Email, "ĐỔI ĐIỂM LẤY QUÀ - MILKSTORE", temp + temp1);
                user.Points = user.Points - dem;
                await _unitOfWork.GetRepository<ApplicationUser>().UpdateAsync(user);
                await _unitOfWork.SaveAsync();
            }
            OrderGift existingOGift = await _unitOfWork.GetRepository<OrderGift>().GetByIdAsync(id)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! OrderGift null");


            // Cập nhật thông tin sản phẩm bằng cách ánh xạ từ DTO
            _mapper.Map(orderGiftModel, existingOGift);
            existingOGift.LastUpdatedTime = DateTime.UtcNow;
            await _unitOfWork.GetRepository<OrderGift>().UpdateAsync(existingOGift);
            await _unitOfWork.SaveAsync();
        }
        //public async Task SendMail_OrderGift(string? id, OrderGiftModel orderGiftModel)
        //{
        //    DateTime currentDate = DateTime.Now;
        //    DateTime futureDate = currentDate.AddDays(3);
        //    DateTime futureDate2 = currentDate.AddDays(5);
        //    string temp = "Thời gian giao dự kiến từ " + futureDate.ToString("dd/MM/yyyy") + " đến " + futureDate2.ToString("dd/MM/yyyy");
        //    string productname = ""; // lấy thông tin theo id
        //    ApplicationUser user = await _unitOfWork.GetRepository<ApplicationUser>().GetByIdAsync(OG.UserID);
        //    int dem = 0;

        //    IEnumerable<OrderDetailGift> ODG = await _unitOfWork.GetRepository<OrderDetailGift>().GetAllAsync();
        //    foreach (var item in ODG)
        //    {

        //        if (item.OrderGiftId == id)
        //        {
        //            Gift gift = await _unitOfWork.GetRepository<Gift>().GetByIdAsync(item.GiftId);
        //            dem += gift.point * item.quantity;
        //            productname += " " + gift.Products.ProductName + " Số lượng: " + item.quantity;
        //        }
        //    }
        //    string temp1 = " Quà tặng gồm: " + productname;
        //    if (orderGiftModel.Status == "Confirmed")
        //    {
        //        _emailService.SendEmailAsync(user.Email, "ĐỔI ĐIỂM LẤY QUÀ - MILKSTORE", temp + temp1);
        //        user.Points = user.Points - dem;
        //        await _unitOfWork.GetRepository<ApplicationUser>().UpdateAsync(user);
        //        await _unitOfWork.SaveAsync();
        //    }
        //}
    }
}
