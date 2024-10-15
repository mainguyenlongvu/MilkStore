using AutoMapper;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.ModelViews.OrderDetailGiftModelView;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.Repositories.Context;
using MilkStore.Repositories.Entity;
using OrderGiftStatus = MilkStore.Contract.Repositories.Entity.OrderGiftStatus;
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
            if (temppoint == 0)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Not enough points!!!");
            }
            int temppoint1 = 0;
            Gift G = await _unitOfWork.GetRepository<Gift>().GetByIdAsync(orderDetailGiftModel.GiftId)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Gift null");
            temppoint1 = G.point * orderDetailGiftModel.quantity;
            if (temppoint < temppoint1)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Not enough points!!!");
                
            }
            ApplicationUser user = await _unitOfWork.GetRepository<ApplicationUser>().GetByIdAsync(OG.UserID) ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! user null");
            user.Points = user.Points - temppoint1;
            await _unitOfWork.GetRepository<ApplicationUser>().UpdateAsync(user);
            await _unitOfWork.SaveAsync();
            OrderDetailGift newOrderDetailGift = _mapper.Map<OrderDetailGift>(orderDetailGiftModel);
            IEnumerable<OrderDetailGift> newODG = await _unitOfWork.GetRepository<OrderDetailGift>().GetAllAsync();
            foreach (var item in newODG)
            {
                if (item.OrderGiftId == orderDetailGiftModel.OrderGiftId)
                {
                    if (item.GiftId == orderDetailGiftModel.GiftId)
                    {
                        OrderDetailGift newOrderDetailGift1 = await _unitOfWork.GetRepository<OrderDetailGift>().GetByIdAsync(item.Id) ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! OrderDetailGift null");
                        newOrderDetailGift1.quantity += orderDetailGiftModel.quantity;
                        newOrderDetailGift1.LastUpdatedTime = DateTime.UtcNow;
                        await _unitOfWork.GetRepository<OrderDetailGift>().UpdateAsync(newOrderDetailGift1);
                        await _unitOfWork.SaveAsync();
                        return;
                    }

                }
            }
            if(OG.Status == OrderGiftStatus.Isnull)
            {
                newOrderDetailGift.Shipfee = 0;
            }    
            newOrderDetailGift.CreatedTime = DateTime.UtcNow;
            newOrderDetailGift.LastUpdatedTime = DateTime.UtcNow;
            newOrderDetailGift.DeletedTime = null; 

            await _unitOfWork.GetRepository<OrderDetailGift>().InsertAsync(newOrderDetailGift);
            await _unitOfWork.SaveAsync();

        }
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

                if ( Gift.DeletedTime == null)
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
