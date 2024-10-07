using Microsoft.EntityFrameworkCore;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.ModelViews.ResponseDTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.Services.Service
{
    public class StatisticalProductService : IStatisticalProductService
    {
        private readonly IUnitOfWork _unitOfWork;

        public StatisticalProductService(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        // Phương thức lấy top 10 sản phẩm bán chạy nhất
        public async Task<List<ProductSalesDTO>> GetTopSellingProducts(int topN, DateTime? startDate, DateTime? endDate, string? productName, string? categoryName)
        {
            var query = from od in _unitOfWork.GetRepository<OrderDetails>().Entities
                        join o in _unitOfWork.GetRepository<Order>().Entities on od.OrderID equals o.Id
                        join p in _unitOfWork.GetRepository<Products>().Entities on od.ProductID equals p.Id
                        join c in _unitOfWork.GetRepository<Category>().Entities on p.CategoryId equals c.Id
                        where o.OrderStatuss == OrderStatus.Delivered
                        select new { od.ProductID, od.Quantity, o.OrderDate, p.ProductName, c.CategoryName };

            // Lọc theo ngày
            if (startDate.HasValue)
            {
                query = query.Where(x => x.OrderDate >= startDate.Value);
            }

            if (endDate.HasValue)
            {
                query = query.Where(x => x.OrderDate <= endDate.Value);
            }

            // Lọc theo tên sản phẩm
            if (!string.IsNullOrEmpty(productName))
            {
                query = query.Where(x => x.ProductName.Contains(productName));
            }

            // Lọc theo thể loại
            if (!string.IsNullOrEmpty(categoryName))
            {
                query = query.Where(x => x.CategoryName.Contains(categoryName));
            }

            // Lấy danh sách 10 sản phẩm bán chạy nhất
            var topSellingProducts = await query
                .GroupBy(x => new { x.ProductID, x.ProductName })
                .Select(g => new ProductSalesDTO
                {
                    ProductId = g.Key.ProductID,
                    TotalSold = g.Sum(x => x.Quantity)
                })
                .OrderByDescending(p => p.TotalSold)
                .Take(topN) // Lấy top N sản phẩm
                .ToListAsync();

            return topSellingProducts;
        }

        public async Task<List<ProductStockDTO>> GetLowStockProducts(int threshold)
        {
            var lowStockProducts = await _unitOfWork.GetRepository<Products>().Entities
                .Where(p => p.QuantityInStock <= threshold)
                .Select(p => new ProductStockDTO
                {
                    Id = p.Id,
                    ProductName = p.ProductName,
                    QuantityInStock = p.QuantityInStock,
                    CategoryId = p.CategoryId
                })
                .ToListAsync();

            return lowStockProducts;
        }
    }

}
