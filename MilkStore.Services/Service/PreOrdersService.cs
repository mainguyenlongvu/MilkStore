using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.Core.Utils;
using MilkStore.ModelViews.PreOrdersModelView;
using MilkStore.Repositories.Context;
using MilkStore.Repositories.Entity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.Services.Service
{
    public class PreOrdersService : IPreOrdersService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IEmailService _emailService;
        private readonly IMapper _mapper;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IUserService _userService;
        public PreOrdersService(IUnitOfWork unitOfWork, IMapper mapper, IEmailService emailService, IHttpContextAccessor httpContextAccessor, IUserService userService)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _emailService = emailService;
            _httpContextAccessor = httpContextAccessor;
            _userService = userService;
        }

        public async Task CreatePreOrders(PreOrdersModelView preOrdersModel)
        {
            Products? product = await _unitOfWork.GetRepository<Products>()
                .Entities
                .FirstOrDefaultAsync(p => p.Id == preOrdersModel.ProductID);

            if (product == null)
            {
                throw new KeyNotFoundException($"Product with ID {preOrdersModel.ProductID} was not found.");
            }
            //Check sản phẩm còn hàng thì không lên pre-order
            if (product.QuantityInStock > 0)
            {
                throw new InvalidOperationException($"The product {product.ProductName} is currently available." +
                    $" Please check and purchase the product on our product page.");
            }

            PreOrders newPreOrder = _mapper.Map<PreOrders>(preOrdersModel);
            newPreOrder.CreatedTime = DateTime.UtcNow;
            await _unitOfWork.GetRepository<PreOrders>().InsertAsync(newPreOrder);
            await _unitOfWork.SaveAsync();

            string userID = _httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value;
            var user = await _userService.GetUser(userID);
            if (!user.Any())
            {
                throw new KeyNotFoundException($"User with ID {userID} was not found.");
            }
            string toEmail = _httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.Email).Value;
            string subject = "Xác nhận đặt hàng trước";
            string body = $@"
                Xin chào {user.FirstOrDefault().UserName},

                Cảm ơn bạn đã đặt hàng sản phẩm {product.ProductName}. 
                Sản phẩm bạn đặt hàng hiện đang hết hàng. Chúng tôi sẽ thông báo cho bạn ngay khi sản phẩm có sẵn trong kho.                

                Thông tin đơn hàng:
                - Mã sản phẩm: {product.Id}
                - Tên sản phẩm: {product.ProductName}
                - Số lượng đặt trước: {preOrdersModel.Quantity}
    
                Trân trọng,
                Đội ngũ MilkStore";

            await _emailService.SendEmailAsync(toEmail, subject, body);
        }

        public async Task DeletePreOrders(string id)
        {
            if (string.IsNullOrWhiteSpace(id))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Please enter postID!");
            }
            PreOrders? preOrder = await _unitOfWork.GetRepository<PreOrders>().GetByIdAsync(id)
                 ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"No pre-order found with {id}");
            if (preOrder.DeletedTime != null)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "This pre-order has already been deleted!");
            }
            preOrder.DeletedTime = CoreHelper.SystemTimeNow;
            await _unitOfWork.GetRepository<PreOrders>().UpdateAsync(preOrder);
            await _unitOfWork.SaveAsync();
        }

        public async Task<IEnumerable<PreOrders>> GetPreOrders(string? id, int page, int pageSize)
        {
            if (id == null)
            {
                IQueryable<PreOrders>? query = _unitOfWork.GetRepository<PreOrders>()
                    .Entities
                    .Where(detail => detail.DeletedTime == null)
                    .OrderBy(detail => detail.ProductID);


                BasePaginatedList<PreOrders>? paginated = await _unitOfWork.GetRepository<PreOrders>()
                .GetPagging(query, page, pageSize);

                return paginated.Items;

            }
            else
            {
                PreOrders? preord = await _unitOfWork.GetRepository<PreOrders>()
                    .Entities
                    .FirstOrDefaultAsync(r => r.Id == id && r.DeletedTime == null);
                if (preord == null)
                {
                    throw new KeyNotFoundException($"Pre-order have ID: {id} was not found.");
                }
                return _mapper.Map<List<PreOrders>>(preord);
            }
        }

        public async Task UpdatePreOrders(string id, PreOrdersModelView preOrdersModel)
        {
            string userID = _httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value;
            if (!string.IsNullOrWhiteSpace(userID))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Please log in!");
            }
            PreOrders? preOrders = await _unitOfWork.GetRepository<PreOrders>().GetByIdAsync(id)
             ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"No pre-order found with {id}!");

            _mapper.Map(preOrdersModel, preOrders);

            preOrders.LastUpdatedTime = CoreHelper.SystemTimeNow;
            preOrders.LastUpdatedBy = userID;

            await _unitOfWork.GetRepository<PreOrders>().UpdateAsync(preOrders);
            await _unitOfWork.SaveAsync();
        }
    }
}
