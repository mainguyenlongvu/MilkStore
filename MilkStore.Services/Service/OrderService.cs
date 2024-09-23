using MilkStore.Contract.Services.Interface;
using MilkStore.ModelViews.OrderModelViews;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Core.Utils;
using MilkStore.Repositories.Context;
using Microsoft.EntityFrameworkCore;
using MilkStore.ModelViews.ResponseDTO;
using AutoMapper;
using MilkStore.Repositories.Entity;
using System.Security.Cryptography;
using MilkStore.ModelViews.ProductsModelViews;
using MilkStore.Services.EmailSettings;

namespace MilkStore.Services.Service
{
    public class OrderService : IOrderService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly DatabaseContext _context;
        protected readonly DbSet<Order> _dbSet;
        private readonly IMapper _mapper;
        private readonly EmailService _emailService;
        public OrderService(IUnitOfWork unitOfWork, DatabaseContext context, IMapper mapper, EmailService emailService)
        {
            _unitOfWork = unitOfWork;
            _context = context;
            _dbSet = _context.Set<Order>();
            _mapper = mapper;
            _emailService = emailService;
        }

        private OrderResponseDTO MapToOrderResponseDto(Order order)
        {
            return _mapper.Map<OrderResponseDTO>(order);
        }
        
        public async Task<IEnumerable<OrderResponseDTO>> GetAsync(string? id)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(id))
                {
                    List<Order> listOrder = await _dbSet.Where
                        (e => !EF.Property<DateTimeOffset?>(e, "DeletedTime").HasValue)
                        .ToListAsync();
                    return listOrder.Select(MapToOrderResponseDto).ToList();
                }
                else
                {
                    Order ord = await _unitOfWork.GetRepository<Order>().Entities
                        .FirstOrDefaultAsync(or => or.Id == id && !or.DeletedTime.HasValue)
                        ?? throw new KeyNotFoundException($"Order với ID {id} không tìm thấy hoặc đã bị xóa.");
                    return new List<OrderResponseDTO> { MapToOrderResponseDto(ord) };
                }
            }
            catch (KeyNotFoundException ex)
            {
                // Log lỗi chi tiết và trả về BadRequest
                // Bạn có thể log lỗi tại đây nếu cần
                throw new ArgumentException(ex.Message);
            }
            catch (Exception ex)
            {
                // Log lỗi không mong muốn và trả về lỗi
                // Tránh để lộ lỗi chi tiết cho phía client
                throw new ApplicationException("Đã xảy ra lỗi khi xử lý yêu cầu của bạn.", ex);
            }
        }

        public async Task AddAsync(OrderModelView ord)
        {
            try
            {
                // Sử dụng mapper để ánh xạ từ OrderModelView sang Order
                Order item = _mapper.Map<Order>(ord);
                item.OrderDate = CoreHelper.SystemTimeNow;
                DateTimeOffset d1 = item.OrderDate.AddDays(3);
                DateTimeOffset d2 = item.OrderDate.AddDays(5);
                item.estimatedDeliveryDate = $"từ {d1:dd/MM/yyyy} đến {d2:dd/MM/yyyy}";

                // Đảm bảo gán các giá trị khác không được ánh xạ từ model view
                item.TotalAmount = 0;
                item.DiscountedAmount = 0;

                // Kiểm tra sự tồn tại của User
                if (await _unitOfWork.GetRepository<ApplicationUser>().Entities
                        .AnyAsync(u => u.Id == ord.UserId) == false)
                {
                    throw new KeyNotFoundException($"User với ID {ord.UserId} không tồn tại.");
                }

                await _unitOfWork.GetRepository<Order>().InsertAsync(item);
                await _unitOfWork.SaveAsync();
            }
            catch (KeyNotFoundException ex) 
            {
                // Log lỗi chi tiết và trả về BadRequest
                // Bạn có thể log lỗi tại đây nếu cần
                throw new ArgumentException(ex.Message);
            }
            catch (Exception ex)
            {
                // Log lỗi không mong muốn và trả về lỗi
                // Tránh để lộ lỗi chi tiết cho phía client
                throw new ApplicationException("Đã xảy ra lỗi khi xử lý yêu cầu của bạn.", ex);
            }
        }

        public async Task UpdateAsync(string id, OrderModelView ord)
        {
            try
            {
                // Lấy đối tượng hiện tại từ cơ sở dữ liệu
                Order orderss = await _unitOfWork.GetRepository<Order>().Entities
                    .FirstOrDefaultAsync(or => or.Id == id && !or.DeletedTime.HasValue)
                    ?? throw new KeyNotFoundException($"Order với ID {id} không tìm thấy hoặc đã bị xóa.");

                // Sử dụng AutoMapper để ánh xạ những thay đổi
                _mapper.Map(ord, orderss);  // Chỉ ánh xạ những thuộc tính có giá trị khác biệt

                if (await _unitOfWork.GetRepository<ApplicationUser>().Entities
                        .AnyAsync(u => u.Id == ord.UserId) == false)
                {
                    throw new KeyNotFoundException($"User với ID {ord.UserId} không tồn tại.");
                }

                // Cập nhật thời gian cập nhật
                orderss.LastUpdatedTime = CoreHelper.SystemTimeNow;

                // Lưu thay đổi vào cơ sở dữ liệu
                await _unitOfWork.GetRepository<Order>().UpdateAsync(orderss);
                await _unitOfWork.SaveAsync();
            }
            catch (KeyNotFoundException ex)
            {
                // Log lỗi chi tiết và trả về BadRequest
                // Bạn có thể log lỗi tại đây nếu cần
                throw new ArgumentException(ex.Message);
            }
            catch (Exception ex)
            {
                // Log lỗi không mong muốn và trả về lỗi
                // Tránh để lộ lỗi chi tiết cho phía client
                throw new ApplicationException("Đã xảy ra lỗi khi xử lý yêu cầu của bạn.", ex);
            }
        }

        //Cập nhật TotalAmount
        public async Task UpdateToTalAmount (string id)
        {

            try
            {
                Order ord = await _unitOfWork.GetRepository<Order>().Entities
                .FirstOrDefaultAsync(or => or.Id == id && !or.DeletedTime.HasValue)
                ?? throw new KeyNotFoundException($"Order với ID {id} không tìm thấy hoặc đã bị xóa.");
                List<OrderDetails> lstOrd = await _unitOfWork.GetRepository<OrderDetails>().Entities
                    .Where(ordt => ordt.OrderID == id && !ordt.DeletedTime.HasValue).ToListAsync();
                ord.TotalAmount = lstOrd.Sum(o => o.TotalAmount);

                double discountAmount = 0;
                //Tính thành tiền áp dụng ưu đãi
                Voucher vch = await _unitOfWork.GetRepository<Voucher>().Entities
                    .FirstOrDefaultAsync(v => v.Id == ord.VoucherId && !v.DeletedTime.HasValue);
                if (vch is
                    {
                        ExpiryDate: var expiryDate,
                        LimitSalePrice: var limitSalePrice,
                        SalePercent: var salePercent,
                        UsedCount: var usedCount,
                        UsingLimit: var usingLimit
                    })
                {
                    if (expiryDate > ord.OrderDate
                        && Convert.ToDouble(limitSalePrice) <= ord.TotalAmount
                        && usedCount < usingLimit)
                    {
                        discountAmount = (ord.TotalAmount * salePercent) / 100.0;
                    }
                }
                ord.DiscountedAmount = ord.TotalAmount - discountAmount;
                await _unitOfWork.GetRepository<Order>().UpdateAsync(ord);
                await _unitOfWork.SaveAsync();
            }
            catch (KeyNotFoundException ex)
            {
                // Log lỗi chi tiết và trả về BadRequest
                // Bạn có thể log lỗi tại đây nếu cần
                throw new ArgumentException(ex.Message);
            }
            catch (Exception ex)
            {
                // Log lỗi không mong muốn và trả về lỗi
                // Tránh để lộ lỗi chi tiết cho phía client
                throw new ApplicationException("Đã xảy ra lỗi khi xử lý yêu cầu của bạn.", ex);
            }
        }

        public async Task AddVoucher(string id, string voucherId)
        {
            try
            {
                Order orderss = await _unitOfWork.GetRepository<Order>().Entities
                    .FirstOrDefaultAsync(or => or.Id == id && !or.DeletedTime.HasValue)
                    ?? throw new KeyNotFoundException($"Order với ID {id} không tìm thấy hoặc đã bị xóa");

                // Kiểm tra sự tồn tại của Voucher
                Voucher vch = await _unitOfWork.GetRepository<Voucher>().Entities
                        .FirstOrDefaultAsync(v => v.Id == voucherId && !v.DeletedTime.HasValue)
                        ?? throw new KeyNotFoundException($"Voucher với ID {voucherId} không tồn tại.");

                if (vch.ExpiryDate < orderss.OrderDate) 
                {
                    throw new KeyNotFoundException($"Voucher đã hết thời hạn áp dụng.");
                }
                vch.UsedCount++;
                await _unitOfWork.GetRepository<Voucher>().UpdateAsync(vch);

                orderss.VoucherId = vch.Id;
                await _unitOfWork.GetRepository<Order>().UpdateAsync(orderss);
                await _unitOfWork.SaveAsync();
                await UpdateToTalAmount(orderss.Id);
            }
            catch (KeyNotFoundException ex)
            {
                // Log lỗi chi tiết và trả về BadRequest
                // Bạn có thể log lỗi tại đây nếu cần
                throw new ArgumentException(ex.Message);
            }
            catch (Exception ex)
            {
                // Log lỗi không mong muốn và trả về lỗi
                // Tránh để lộ lỗi chi tiết cho phía client
                throw new ApplicationException("Đã xảy ra lỗi khi xử lý yêu cầu của bạn.", ex);
            }
        }

        public async Task DeleteAsync(string id)
        {
            try
            {
                Order orderss = await _unitOfWork.GetRepository<Order>().Entities
                    .FirstOrDefaultAsync(or => or.Id == id && !or.DeletedTime.HasValue)
                    ?? throw new KeyNotFoundException($"Order với ID {id} không tìm thấy hoặc đã bị xóa");
                orderss.DeletedTime = CoreHelper.SystemTimeNow;
                await _unitOfWork.GetRepository<Order>().UpdateAsync(orderss);
                await _unitOfWork.SaveAsync();
            }
            catch (KeyNotFoundException ex)
            {
                // Log lỗi chi tiết và trả về BadRequest
                // Bạn có thể log lỗi tại đây nếu cần
                throw new ArgumentException(ex.Message);
            }
            catch (Exception ex)
            {
                // Log lỗi không mong muốn và trả về lỗi
                // Tránh để lộ lỗi chi tiết cho phía client
                throw new ApplicationException("Đã xảy ra lỗi khi xử lý yêu cầu của bạn.", ex);
            }
        }

        public async Task GetStatus_Mail(string? id)
        {
            Order order = await _unitOfWork.GetRepository<Order>().GetByIdAsync(id);
            ApplicationUser user = await _unitOfWork.GetRepository<ApplicationUser>().GetByIdAsync(order.UserId);
            if (order != null && order.DeletedTime == null)
            {
                if (order.UserId == user.Id)
                {
                    if (order.Status.Equals("successful payment") && order.PaymentMethod.Equals("Online"))
                    {
                        _emailService.SendEmailAsync(user.Email, "Đơn hàng " + order.TotalAmount + " thanh toán thành công", "Thời gian giao hàng dự kiến " + order.estimatedDeliveryDate + ". Cảm ơn quý khách đã mua hàng tại MilkStore");
                        order.Status = "successful payment - DONE";
                        await _unitOfWork.GetRepository<Order>().UpdateAsync(order);
                        await _unitOfWork.SaveAsync();
                    }
                    if (order.PaymentMethod.Equals("Offline"))
                    {
                        _emailService.SendEmailAsync(user.Email, "Đơn hàng " + order.TotalAmount + " thanh toán khi nhận hàng", "Thời gian giao hàng dự kiến " + order.estimatedDeliveryDate + ". Cảm ơn quý khách đã mua hàng tại MilkStore");
                        order.Status = "successful payment - DONE";
                        await _unitOfWork.GetRepository<Order>().UpdateAsync(order);
                        await _unitOfWork.SaveAsync();
                    }
                }

            }
        }
    }
}
