using AutoMapper;
using Microsoft.EntityFrameworkCore;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.Core.Utils;
using MilkStore.ModelViews.ProductsModelViews;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.Repositories.Context;
using Org.BouncyCastle.Math.Field;

namespace MilkStore.Services.Service
{
    public class ProductsService : IProductsService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly DatabaseContext context;
        private readonly IMapper _mapper;
        public ProductsService(DatabaseContext context, IUnitOfWork unitOfWork, IMapper mapper)
        {
            this.context = context;
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }
        public async Task<IEnumerable<ProductResponseDTO>> GetProductsName(string? ProductdName, string? CategoryName)
        {
            IEnumerable<Products> products = await _unitOfWork.GetRepository<Products>().GetAllAsync();
            if(CategoryName == null && ProductdName == null)
            {
                return _mapper.Map<IEnumerable<ProductResponseDTO>>(products);
            }    
            if (CategoryName == null)
            {
                products = products.Where(p => p.ProductName.Contains(ProductdName, StringComparison.OrdinalIgnoreCase) && p.DeletedTime == null);
            }
            if (ProductdName == null)
            {
                string temp = "";
                IEnumerable<Category> cte = await _unitOfWork.GetRepository<Category>().GetAllAsync();
                foreach (Category c in cte)
                {
                    if (c.CategoryName == CategoryName && c.DeletedTime == null)
                    {
                        temp = c.Id;
                    }
                }
                products = products.Where(p => p.CategoryId.Contains(temp, StringComparison.OrdinalIgnoreCase) && p.DeletedTime == null);
            }

            return _mapper.Map<IEnumerable<ProductResponseDTO>>(products);
        }
        public async Task CreateProducts(ProductsModel productsModel)
        {
            IEnumerable<Products> pd = await _unitOfWork.GetRepository<Products>().GetAllAsync();
            foreach (Products p in pd)
            {
                if(p.ProductName.Equals(productsModel.ProductName, StringComparison.OrdinalIgnoreCase))
                {
                    throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Same product name");
                }    
            }
            Products newProduct = _mapper.Map<Products>(productsModel);
            newProduct.CreatedTime = DateTime.UtcNow;

            await _unitOfWork.GetRepository<Products>().InsertAsync(newProduct);
            await _unitOfWork.SaveAsync();
            
        }
        public async Task DeleteProducts(string id)
        {
            if(string.IsNullOrWhiteSpace(id))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Input wrong id");
            }    
            Products product = await _unitOfWork.GetRepository<Products>().GetByIdAsync(id)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Product null");

            if (product.DeletedTime != null)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, $"Doesn't exist:{id}");
            }
            product.DeletedTime = DateTime.UtcNow;
            await _unitOfWork.GetRepository<Products>().UpdateAsync(product);
            await _unitOfWork.SaveAsync();

        }


        public async Task<BasePaginatedList<ProductResponseDTO>> GetProducts(string? id, int pageIndex, int pageSize)
        {
            IQueryable<Products> query = _unitOfWork.GetRepository<Products>().Entities;
            if(pageIndex==0 || pageSize == 0)
            {
                pageSize = 5;
                pageIndex = 1;
            }    
            if (!string.IsNullOrWhiteSpace(id))
            {
                query = query.Where(p => p.Id == id && p.DeletedTime == null);

                var product = await query.FirstOrDefaultAsync();
                if (product != null)
                {
                    var productModel = _mapper.Map<ProductResponseDTO>(product);
                    return new BasePaginatedList<ProductResponseDTO>(new List<ProductResponseDTO> { productModel }, 1, 1, 1);
                }
                else
                {
                    return new BasePaginatedList<ProductResponseDTO>(new List<ProductResponseDTO>(), 0, pageIndex, pageSize);
                }
            }
            query = query.Where(p => p.DeletedTime == null);

            BasePaginatedList<Products> paginatedList = await _unitOfWork.GetRepository<Products>().GetPagging(query, pageIndex, pageSize);

            var productsModel = _mapper.Map<IEnumerable<ProductResponseDTO>>(paginatedList.Items);
            return new BasePaginatedList<ProductResponseDTO>(productsModel.ToList(), paginatedList.TotalPages, pageIndex, pageSize);
        }


        private async Task UpdatePreOrdersDeletedTime(string productId)
        {
              
            var preOrders = await _unitOfWork.GetRepository<PreOrders>()
                .Entities
                .Where(p => p.ProductID == productId && p.DeletedTime == null)
                .ToListAsync();

            foreach (var preOrder in preOrders)
            {
                preOrder.DeletedTime = CoreHelper.SystemTimeNow;
                await _unitOfWork.GetRepository<PreOrders>().UpdateAsync(preOrder);
            }

            await _unitOfWork.SaveAsync();
        }

        public async Task UpdateProducts(string id, ProductsModel productsModel)
        {
            IEnumerable<Products> pd = await _unitOfWork.GetRepository<Products>().GetAllAsync();
            foreach (Products p in pd)
            {
                if (p.ProductName.Equals(productsModel.ProductName, StringComparison.OrdinalIgnoreCase))
                {
                    throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Same product name");
                }
            }
            Products product = await _unitOfWork.GetRepository<Products>().GetByIdAsync(id)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, $"Doesn't exist{id}");
            var oldQuantityInStock = product.QuantityInStock;

            _mapper.Map(productsModel, product);
            product.LastUpdatedTime = CoreHelper.SystemTimeNow;

            await _unitOfWork.GetRepository<Products>().UpdateAsync(product);
            await _unitOfWork.SaveAsync();

            if (product.QuantityInStock > 0 && oldQuantityInStock <= 0)
            {
                //Tự động xóa Pre-order khi số lượng sản phẩm > 0
                await UpdatePreOrdersDeletedTime(product.Id);
            }
        }
    }
}
