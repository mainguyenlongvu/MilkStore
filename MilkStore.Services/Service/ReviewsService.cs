using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.Core.Utils;
using MilkStore.ModelViews.ReviewsModelView;
using MilkStore.Repositories.Context;
using MilkStore.Services.EmailSettings;
using System.Security.Claims;

namespace MilkStore.Services.Service
{
    public class ReviewsService : IReviewsService
    {
        private readonly IUnitOfWork _unitOfWork;        
        private readonly IMapper _mapper;
        private readonly IEmailService _emailService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public ReviewsService(IUnitOfWork unitOfWork, IMapper mapper, IEmailService emailService, IHttpContextAccessor httpContextAccessor)
        {            
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _emailService = emailService;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task CreateReviews(ReviewsModel reviewsModel)
        {            
            OrderDetails? orderDetail = await _unitOfWork.GetRepository<OrderDetails>().GetByIdAsync(reviewsModel.OrderDetailID);
            if (orderDetail == null)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không tìm thấy chi tiết đơn hàng nào với mã {reviewsModel.OrderDetailID}!!");
            }
                        
            Order? order = await _unitOfWork.GetRepository<Order>().GetByIdAsync(orderDetail.OrderID);
            string? userID = _httpContextAccessor.HttpContext.User?.FindFirst(ClaimTypes.NameIdentifier).Value;
            string? userEmail = _httpContextAccessor.HttpContext.User?.FindFirst(ClaimTypes.Email).Value;

            if(string.IsNullOrWhiteSpace(userID) || string.IsNullOrWhiteSpace(userEmail))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Vui lòng đăng nhập vào bằng tài khoản đã xác thực!");
            }
            if (order == null || order.UserId.ToString() != userID)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Bạn không có quyền đánh giá sản phẩm này!");
            }
            //Kiểm tra đơn hàng đã được giao và thanh toán
            if (order.OrderStatuss != OrderStatus.Delivered && order.PaymentStatuss != PaymentStatus.Paid)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.Forbidden, "Bạn chỉ có thể đánh giá đơn hàng sau khi đơn hàng đã được giao và thanh toán!");
            }
            var productInOrder = order.OrderDetailss.Where(od => od.ProductID.Contains(orderDetail.ProductID)).FirstOrDefault();
            if (productInOrder == null)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không tìm thấy mã sản phẩm {orderDetail.ProductID} trong đơn hàng!!");
            }
            Review newReview = _mapper.Map<Review>(reviewsModel);
            newReview.UserID = Guid.Parse(userID);
            newReview.ProductsID = orderDetail.ProductID;
            newReview.OrderID = orderDetail.OrderID;
            newReview.CreatedTime = CoreHelper.SystemTimeNow;
            newReview.CreatedBy = userID;
            await _unitOfWork.GetRepository<Review>().InsertAsync(newReview);
            await _unitOfWork.SaveAsync();

            // Gửi email phản hồi
            if (!string.IsNullOrEmpty(userEmail))
            {
                var subject = "Cảm ơn bạn đã đánh giá sản phẩm!";
                var body = $@"
            <p>Xin chào,</p>
            <p>Cảm ơn bạn đã đánh giá sản phẩm {productInOrder.Products.ProductName}. Đánh giá của bạn giúp chúng tôi cải thiện dịch vụ.</p>
            <p>Thông tin đánh giá:</p>
            <ul>
                <li>Sản phẩm: {productInOrder.Products.ProductName}</li>
                <li>Đánh giá: {reviewsModel.Rating} sao</li>
                <li>Nhận xét: {reviewsModel.Comment}</li>
            </ul>
            <p>Trân trọng,<br>MilkStore</p>
        ";
                await _emailService.SendEmailAsync(userEmail, subject, body);
            }
        }

        public async Task DeletReviews(string id)
        {
            Review review = await _unitOfWork.GetRepository<Review>().GetByIdAsync(id);
            if (review == null)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.BadRequest, $"Không tìm thấy đánh giá nào có mã {id}!!");
            }
            review.DeletedTime = CoreHelper.SystemTimeNow;
            review.DeletedBy = "Admin";
            await _unitOfWork.GetRepository<Review>().UpdateAsync(review);
            await _unitOfWork.SaveAsync();
        }

        public async Task<IEnumerable<Review>> GetReviews(string? id, int page, int pageSize)
        {
            if (id == null)
            {
                var query = _unitOfWork.GetRepository<Review>()
                    .Entities
                    .Where(detail => detail.DeletedTime == null)
                    .OrderBy(detail => detail.ProductsID);


                var paginated = await _unitOfWork.GetRepository<Review>()
                .GetPagging(query, page, pageSize);

                return paginated.Items;

            }
            else
            {
                var review = await _unitOfWork.GetRepository<Review>()
                    .Entities
                    .FirstOrDefaultAsync(r => r.Id == id && r.DeletedTime == null);
                if (review == null)
                {
                    throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không tìm thấy đánh giá nào có mã {id}!!");
                }
                return _mapper.Map<List<Review>>(review);
            }

        }

        public async Task<Review> UpdateReviews(string id, ReviewsModel reviewsModel)
        {

            Review? review = await _unitOfWork.GetRepository<Review>().GetByIdAsync(id);            
            if (review == null)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không tìm thấy đánh giá nào có mã {id}!!");
            }
            string userID = _httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value;
            if (string.IsNullOrWhiteSpace(userID))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Vui lòng đăng nhập vào bằng tài khoản đã xác thực!");
            }
            _mapper.Map(reviewsModel, review);            
            review.LastUpdatedTime = CoreHelper.SystemTimeNow;            
            review.LastUpdatedBy = userID;
            await _unitOfWork.GetRepository<Review>().UpdateAsync(review);
            await _unitOfWork.SaveAsync();
            return review;
        }
    }
}
