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
            newPreOrder.CreatedTime = CoreHelper.SystemTimeNow;
            await _unitOfWork.GetRepository<PreOrders>().InsertAsync(newPreOrder);
            await _unitOfWork.SaveAsync();

            string userID = _httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value;
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
                    throw new KeyNotFoundException($"Pre-order với mã: {id} không tìm thấy.");
                }
                return _mapper.Map<List<PreOrders>>(preord);
            }
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

            preOrders.LastUpdatedTime = CoreHelper.SystemTimeNow;
            preOrders.LastUpdatedBy = userID;

            await _unitOfWork.GetRepository<PreOrders>().UpdateAsync(preOrders);
            await _unitOfWork.SaveAsync();
        }
    }
}
