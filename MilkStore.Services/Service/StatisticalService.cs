using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.ModelViews.ResponseDTO;


namespace MilkStore.Services.Service
{
    public class StatisticalService : IStatisticalService
    {
        private readonly IUnitOfWork _unitOfWork;
        public StatisticalService(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }
        public async Task<double> GetRevenueStats(int? day, int? month, int? year, DateTime? startDate, DateTime? endDate)
        {
            var query = _unitOfWork.GetRepository<Order>().Entities
                .Where(o => o.OrderStatuss == OrderStatus.Delivered);

            if(day.HasValue)
            {
                query = query.Where(o => o.OrderDate.Day == day.Value);
            }
            if(month.HasValue)
            {
                query = query.Where(o => o.OrderDate.Month == month.Value);
            }
            if(year.HasValue)
            {
                query = query.Where(o => o.OrderDate.Year == year.Value);
            }
            if (startDate.HasValue)
            {
                query = query.Where(o => o.OrderDate >= startDate.Value);
            }

            if (endDate.HasValue)
            {
                query = query.Where(o => o.OrderDate <= endDate.Value);
            }

            // Tính tổng doanh thu
            var totalRevenue = await query.SumAsync(o => o.TotalAmount);

            return totalRevenue;
        }
        public async Task<List<EmployeeRevenueDTO>> GetRevenueByEmployee(int? day, int? month, int? year, DateTime? startDate, DateTime? endDate)
        {
            var query = from o in _unitOfWork.GetRepository<Order>().Entities
                        where o.OrderStatuss == OrderStatus.Delivered
                        select new { o.CreatedBy, o.TotalAmount, o.OrderDate };

            if (day.HasValue)
            {
                query = query.Where(o => o.OrderDate.Day == day.Value);
            }
            if (month.HasValue)
            {
                query = query.Where(o => o.OrderDate.Month == month.Value);
            }
            if (year.HasValue)
            {
                query = query.Where(o => o.OrderDate.Year == year.Value);
            }
            if (startDate.HasValue)
            {
                query = query.Where(o => o.OrderDate >= startDate.Value);
            }

            if (endDate.HasValue)
            {
                query = query.Where(o => o.OrderDate <= endDate.Value);
            }

            var revenueByEmployee = await query
                .GroupBy(o => o.CreatedBy)
                .Select(g => new EmployeeRevenueDTO
                {
                    EmployeeId = g.Key,
                    TotalRevenue = g.Sum(o => o.TotalAmount)
                })
                .ToListAsync();

            return revenueByEmployee;
        }
        public async Task<List<ProductRevenueDTO>> GetRevenueByProduct(int? day, int? month, int? year, DateTime? startDate, DateTime? endDate)
        {
            var query = from od in _unitOfWork.GetRepository<OrderDetails>().Entities
                        join o in _unitOfWork.GetRepository<Order>().Entities
                        on od.OrderID equals o.Id
                        where o.OrderStatuss == OrderStatus.Delivered
                        select new { od.ProductID, od.Quantity, od.UnitPrice, o.OrderDate };

            if (day.HasValue)
            {
                query = query.Where(x => x.OrderDate.Day == day.Value);
            }
            if(month.HasValue)
            {
                query = query.Where(x => x.OrderDate.Month == month.Value);
            }
            if(year.HasValue)
            {
                query = query.Where(x => x.OrderDate.Year == year.Value);
            }
            if (startDate.HasValue)
            {
                query = query.Where(x => x.OrderDate >= startDate.Value);
            }

            if (endDate.HasValue)
            {
                query = query.Where(x => x.OrderDate <= endDate.Value);
            }

            var revenueByProduct = await query
                .GroupBy(x => x.ProductID)
                .Select(g => new ProductRevenueDTO
                {
                    ProductId = g.Key,
                    TotalRevenue = g.Sum(x => x.Quantity * x.UnitPrice),
                    TotalQuantity = g.Sum(x => x.Quantity)
                })
                .ToListAsync();

            return revenueByProduct;
        }

        public async Task<List<CategoryRevenueDTO>> GetRevenueByCategory(int? day, int? month, int? year, DateTime? startDate, DateTime? endDate)
        {
            var query = from od in _unitOfWork.GetRepository<OrderDetails>().Entities
                        join p in _unitOfWork.GetRepository<Products>().Entities on od.ProductID equals p.Id
                        join c in _unitOfWork.GetRepository<Category>().Entities on p.CategoryId equals c.Id
                        join o in _unitOfWork.GetRepository<Order>().Entities on od.OrderID equals o.Id
                        where o.OrderStatuss == OrderStatus.Delivered
                        select new { c.CategoryName, od.Quantity, od.UnitPrice, o.OrderDate };

            if (day.HasValue)
            {
                query = query.Where(x => x.OrderDate.Day == day.Value);
            }
            if (month.HasValue)
            {
                query = query.Where(x => x.OrderDate.Month == month.Value);
            }
            if (year.HasValue)
            {
                query = query.Where(x => x.OrderDate.Year == year.Value);
            }
            if (startDate.HasValue)
            {
                query = query.Where(x => x.OrderDate >= startDate.Value);
            }

            if (endDate.HasValue)
            {
                query = query.Where(x => x.OrderDate <= endDate.Value);
            }

            var revenueByCategory = await query
                .GroupBy(x => x.CategoryName)
                .Select(g => new CategoryRevenueDTO
                {
                    CategoryName = g.Key,
                    TotalRevenue = g.Sum(x => x.Quantity * x.UnitPrice)
                })
                .ToListAsync();

            return revenueByCategory;
        }


    }
}
