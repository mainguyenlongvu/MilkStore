using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.Core.Utils;
using MilkStore.ModelViews.GiftModelViews;
using MilkStore.ModelViews.OrderDetailGiftModelView;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.Repositories.Context;
using MilkStore.Repositories.Entity;
using MilkStore.Services.EmailSettings;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.Services.Service
{
    public class OrderDetailGiftService : IOrderDetailGiftService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly DatabaseContext context;
        private readonly IMapper _mapper;
        public OrderDetailGiftService(DatabaseContext context, IUnitOfWork unitOfWork, IMapper mapper)
        {
            this.context = context;
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }
        public async Task CreateOrderDetailGift(OrderDetailGiftModel orderDetailGiftModel)
        {
            int temppoint = 0;
            OrderGift OG = await _unitOfWork.GetRepository<OrderGift>().GetByIdAsync(orderDetailGiftModel.OrderGiftId) 
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! OrderGift null");
            temppoint = OG.User.Points;
            int temppoint1 = 0;
            Gift G = await _unitOfWork.GetRepository<Gift>().GetByIdAsync(orderDetailGiftModel.GiftId)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Gift null");
            temppoint1 = G.point * orderDetailGiftModel.quantity;
            if (temppoint < temppoint1)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Not enough points!!!");
            }

            OrderDetailGift newOrderDetailGift = _mapper.Map<OrderDetailGift>(orderDetailGiftModel);
            IEnumerable<OrderDetailGift> newODG = await _unitOfWork.GetRepository<OrderDetailGift>().GetAllAsync();
            //Gift gift = await _unitOfWork.GetRepository<Gift>().GetByIdAsync(newOrderDetailGift.GiftId);
            //OrderGift og = await _unitOfWork.GetRepository<OrderGift>().GetByIdAsync(newOrderDetailGift.OrderGiftId);
            //int temp1 = gift.point;// so sánh points để thỏa điều kiện
            //int temp2 = og.User.Points;// so sánh points để thỏa điều kiện
            foreach (var item in newODG)
            {
                if (item.OrderGiftId == orderDetailGiftModel.OrderGiftId)
                {
                    Console.WriteLine("OrdergiftID: " + item.OrderGiftId);
                    if (item.GiftId == orderDetailGiftModel.GiftId)
                    {
                        Console.WriteLine("GiftId: " + orderDetailGiftModel.GiftId);
                        OrderDetailGift newOrderDetailGift1 = await _unitOfWork.GetRepository<OrderDetailGift>().GetByIdAsync(item.Id) ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! OrderDetailGift null");
                        newOrderDetailGift1.quantity += orderDetailGiftModel.quantity;
                        newOrderDetailGift1.LastUpdatedTime = DateTime.UtcNow;
                        await _unitOfWork.GetRepository<OrderDetailGift>().UpdateAsync(newOrderDetailGift1);
                        await _unitOfWork.SaveAsync();
                    }

                }
            }
            // Đặt các thuộc tính mặc định (nếu có)
            newOrderDetailGift.CreatedTime = DateTime.UtcNow;
            newOrderDetailGift.LastUpdatedTime = DateTime.UtcNow;
            newOrderDetailGift.DeletedTime = null; // Khi tạo mới thì không có DeletedTime

            // Thêm mới vào cơ sở dữ liệu
            await _unitOfWork.GetRepository<OrderDetailGift>().InsertAsync(newOrderDetailGift);
            await _unitOfWork.SaveAsync();

        }

        //public async Task<OrderDetailGift> Check_PointGift(OrderDetailGiftModel orderDetailGiftModel)
        //{
        //    OrderDetailGift ODG = _mapper.Map<OrderDetailGift>(orderDetailGiftModel);
        //    OrderGift og = await _unitOfWork.GetRepository<OrderGift>().GetByIdAsync(orderDetailGiftModel.OrderGiftId);
        //    Gift g = await _unitOfWork.GetRepository<Gift>().GetByIdAsync(orderDetailGiftModel.GiftId);

        //    ApplicationUser user = await _unitOfWork.GetRepository<ApplicationUser>().GetByIdAsync(og.UserID);

        //    if (user.Points >= g.point)
        //    {
        //        return og;
        //    }
        //    return og;
        //}
        public async Task DeleteOrderDetailGift(string id)
        {
            if(string.IsNullOrWhiteSpace(id))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Input wrong id");
            }    
                OrderDetailGift existingOrderDetailGift = await _unitOfWork.GetRepository<OrderDetailGift>().GetByIdAsync(id)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, $"Doesn't exist:{id}");

                existingOrderDetailGift.DeletedTime = DateTime.UtcNow;

            await _unitOfWork.GetRepository<OrderDetailGift>().UpdateAsync(existingOrderDetailGift);
            await _unitOfWork.SaveAsync();
        }

        public async Task<IEnumerable<OrderDetailGiftResponseDTO>> GetOrderDetailGift(string? id)
        {
            if (id == null)
            {
                IEnumerable<OrderDetailGift> Gift = await _unitOfWork.GetRepository<OrderDetailGift>().GetAllAsync();

                Gift = Gift.Where(p => p.DeletedTime == null);

                return _mapper.Map<IEnumerable<OrderDetailGiftResponseDTO>>(Gift);
            }
            else
            {
                // Lấy sản phẩm theo ID
                Gift Gift = await _unitOfWork.GetRepository<Gift>().GetByIdAsync(id) 
                    ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Gift null");

                if ( Gift.DeletedTime == null) // Kiểm tra DeleteTime
                {
                    return new List<OrderDetailGiftResponseDTO> { _mapper.Map<OrderDetailGiftResponseDTO>(Gift) };
                }
                else
                {
                    return new List<OrderDetailGiftResponseDTO>();
                }
            }
        }


        public async Task UpdateOrderDetailGift(string id, OrderDetailGiftModel OrderDetailGiftModel)
        {
            OrderDetailGift existingGift = await _unitOfWork.GetRepository<OrderDetailGift>().GetByIdAsync(id) 
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! OrderDetailGift null");


            _mapper.Map(OrderDetailGiftModel, existingGift);
            existingGift.LastUpdatedTime = DateTime.UtcNow;

            await _unitOfWork.GetRepository<OrderDetailGift>().UpdateAsync(existingGift);
            await _unitOfWork.SaveAsync();
        }
    }
}
