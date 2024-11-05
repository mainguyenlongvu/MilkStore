using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
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
using MilkStore.ModelViews.ResponseDTO;
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

        private readonly UserManager<ApplicationUser> _userManager;
        public PreOrdersService(IUnitOfWork unitOfWork, IMapper mapper, IEmailService emailService, IHttpContextAccessor httpContextAccessor, IUserService userService, UserManager<ApplicationUser> userManager)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _emailService = emailService;
            _httpContextAccessor = httpContextAccessor;
            _userManager = userManager;
        }

        public async Task CreatePreOrders(PreOrdersModelView preOrdersModel)
        {
            string userID = _httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value;
            Products? product = await _unitOfWork.GetRepository<Products>()
                .Entities
                .FirstOrDefaultAsync(p => p.Id == preOrdersModel.ProductID);

            if (product == null)
            {
                throw new KeyNotFoundException($"Sản phẩm với mã {preOrdersModel.ProductID} không tìm thấy.");
            }
            //Check sản phẩm còn hàng thì không lên pre-order

            if (product.QuantityInStock > 0)
            {
                throw new InvalidOperationException($"Sản phẩm {product.ProductName} bạn muốn đặt trước hiện vẫn còn." +
                    $" Vui lòng tham khảo và đặt hàng tại trang sản phẩm của chúng tôi.");
            }

            PreOrders newPreOrder = _mapper.Map<PreOrders>(preOrdersModel);
            newPreOrder.UserID = Guid.Parse(userID);
            newPreOrder.CreatedTime = CoreHelper.SystemTimeNow;
            await _unitOfWork.GetRepository<PreOrders>().InsertAsync(newPreOrder);
            await _unitOfWork.SaveAsync();

            ApplicationUser? user = await _userManager.FindByIdAsync(userID);
            if (user is null)
            {
                throw new KeyNotFoundException($"Người dùng với mã {userID} không tìm thấy.");
            }
            string toEmail = _httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.Email).Value;
            string subject = "Xác nhận đặt hàng trước";
            string body = $@"
                Xin chào {user.UserName},

                Cảm ơn bạn đã đặt hàng sản phẩm {product.ProductName}. 
                Sản phẩm bạn đặt hàng hiện đang hết hàng. Chúng tôi sẽ thông báo cho bạn ngay khi sản phẩm có sẵn trong kho.                

                Thông tin đơn hàng:
                - Mã sản phẩm: {product.Id}
                - Tên sản phẩm: {product.ProductName}
    
                Trân trọng,
                Đội ngũ MilkStore";

            await _emailService.SendEmailAsync(toEmail, subject, body);
        }

        public async Task DeletePreOrders(string id)
        {
            if (string.IsNullOrWhiteSpace(id))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Vui lòng nhập PreOrderID!");
            }
            PreOrders? preOrder = await _unitOfWork.GetRepository<PreOrders>().GetByIdAsync(id)
                 ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không tìm thấy pre-order nào với mã {id}");
            if (preOrder.DeletedTime != null)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Pre-order này đã bị xóa!");
            }
            preOrder.DeletedTime = CoreHelper.SystemTimeNow;
            await _unitOfWork.GetRepository<PreOrders>().UpdateAsync(preOrder);
            await _unitOfWork.SaveAsync();
        }

        public async Task<BasePaginatedList<PreOdersResponseDTO>> GetPreOders(string? id, int pageIndex, int pageSize)
        {
            IQueryable<PreOrders> query = _unitOfWork.GetRepository<PreOrders>().Entities;
            if (pageIndex == 0 || pageSize == 0)
            {
                pageSize = 5;
                pageIndex = 1;
            }
            if (!string.IsNullOrWhiteSpace(id))
            {
                query = query.Where(p => p.Id == id && p.DeletedTime == null);

                var preOrders = await query.FirstOrDefaultAsync();
                if (preOrders != null)
                {
                    var preOdersModel = _mapper.Map<PreOdersResponseDTO>(preOrders);
                    return new BasePaginatedList<PreOdersResponseDTO>(new List<PreOdersResponseDTO> { preOdersModel }, 1, 1, 1);
                }
                else
                {
                    return new BasePaginatedList<PreOdersResponseDTO>(new List<PreOdersResponseDTO>(), 0, pageIndex, pageSize);
                }
            }
            query = query.Where(p => p.DeletedTime == null);

            BasePaginatedList<PreOrders> paginatedList = await _unitOfWork.GetRepository<PreOrders>().GetPagging(query, pageIndex, pageSize);

            var preoderModel = _mapper.Map<IEnumerable<PreOdersResponseDTO>>(paginatedList.Items);
            return new BasePaginatedList<PreOdersResponseDTO>(preoderModel.ToList(), paginatedList.TotalPages, pageIndex, pageSize);
        }

        public async Task UpdatePreOrders(string id, PreOrdersModelView preOrdersModel)
        {
            string userID = _httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value;
            if (!string.IsNullOrWhiteSpace(userID))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Vui lòng đăng nhập vào tài khoản!");
            }
            PreOrders? preOrders = await _unitOfWork.GetRepository<PreOrders>().GetByIdAsync(id)
             ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không có pre-order nào được tìm thấy với mã {id}!");

            _mapper.Map(preOrdersModel, preOrders);
            preOrders.UserID = Guid.Parse(userID);
            preOrders.LastUpdatedTime = CoreHelper.SystemTimeNow;
            preOrders.LastUpdatedBy = userID;

            await _unitOfWork.GetRepository<PreOrders>().UpdateAsync(preOrders);
            await _unitOfWork.SaveAsync();
            Products? product = await _unitOfWork.GetRepository<Products>()
    .Entities
    .FirstOrDefaultAsync(p => p.Id == preOrdersModel.ProductID);
            ApplicationUser? user = await _userManager.FindByIdAsync(userID);
            if (user is null)
            {
                throw new KeyNotFoundException($"Người dùng với mã {userID} không tìm thấy.");
            }
            string toEmail = _httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.Email).Value;
            string subject = $"Thông báo đã có sản phầm {product.ProductName}";
            string body = $@"
    Xin chào {user.UserName},

    Cảm ơn bạn đã đặt hàng sản phẩm {product.ProductName}. 
    Sản phẩm bạn đặt hàng hiện đã có hàng

    Thông tin đơn hàng:
    - Mã sản phẩm: {product.Id}
    - Tên sản phẩm: {product.ProductName}
    
    Trân trọng,
    Đội ngũ MilkStore";

            await _emailService.SendEmailAsync(toEmail, subject, body);
        }
    }
}
