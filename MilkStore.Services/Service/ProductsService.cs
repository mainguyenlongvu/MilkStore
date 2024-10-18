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
using Microsoft.AspNetCore.Http;
namespace MilkStore.Services.Service
{
    public class ProductsService : IProductsService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly DatabaseContext context;
        private readonly IMapper _mapper;

        private readonly ICloudinaryService _cloudinaryService;
        public ProductsService(DatabaseContext context, IUnitOfWork unitOfWork, IMapper mapper, ICloudinaryService cloudinaryService)
        {
            this.context = context;
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _cloudinaryService = cloudinaryService;
        }

        public async Task<BasePaginatedList<ProductResponseDTO>> GetProductsName(string ProductdName, string CategoryName)
        {
            IQueryable<Products> products = _unitOfWork.GetRepository<Products>().Entities;

            if (CategoryName == null && ProductdName == null)
            {
                // Retrieve the list of products and map to DTO
                var productsList = await products.ToListAsync();
                var productsModel = _mapper.Map<List<ProductResponseDTO>>(productsList);
                return new BasePaginatedList<ProductResponseDTO>(productsModel, productsModel.Count, 1, 1);
            }

            if (CategoryName == null)
            {
                products = products.Where(p => p.ProductName.ToLower().Contains(ProductdName.ToLower()) && p.DeletedTime == null);
            }

            if (ProductdName == null)
            {
                string temp = "";
                IEnumerable<Category> cte = await _unitOfWork.GetRepository<Category>().GetAllAsync();
                foreach (Category c in cte)
                {
                    if (c.CategoryName.Equals(CategoryName, StringComparison.OrdinalIgnoreCase) && c.DeletedTime == null)
                    {
                        temp = c.Id;
                        break;
                    }
                }

                products = products.Where(p => p.CategoryId.ToLower().Contains(temp.ToLower()) && p.DeletedTime == null);
            }


            // Retrieve the filtered list and map it to the DTO list
            var filteredProductsList = await products.ToListAsync();
            var productModels = _mapper.Map<List<ProductResponseDTO>>(filteredProductsList);
            return new BasePaginatedList<ProductResponseDTO>(productModels, productModels.Count, 1, 1);
        }

        public async Task CreateProducts(ProductsModel ProductModel)
        {
            IEnumerable<Products> pd = await _unitOfWork.GetRepository<Products>().GetAllAsync();
            foreach (Products p in pd)
            {
                if (p.ProductName.Equals(ProductModel.ProductName, StringComparison.OrdinalIgnoreCase))
                {
                    throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Error!!! Same product name");
                }
            }

            // Xử lý ảnh
            string imageUrl = null;
            if (ProductModel.Image != null)
            {
                // Giả sử bạn đã có ICloudinaryService
                imageUrl = await _cloudinaryService.UploadImageAsync(ProductModel.Image);
            }

            // Ánh xạ từ CreateProductModel sang Products
            Products newProduct = _mapper.Map<Products>(ProductModel);

            // Thiết lập các thuộc tính còn lại
            newProduct.ImageUrl = imageUrl; // Lưu URL của ảnh vào thuộc tính ImageUrl
            newProduct.CreatedTime = DateTime.UtcNow;

            await _unitOfWork.GetRepository<Products>().InsertAsync(newProduct);
            await _unitOfWork.SaveAsync();
        }

        public async Task DeleteProducts(string id)
        {
            if (string.IsNullOrWhiteSpace(id))
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

        public async Task<BasePaginatedList<ProductResponseDTO>> GetProductByNameId(string id, int pageIndex, int pageSize, string ProductdName, string CategoryName)
        {
            if (pageIndex == 0 || pageSize == 0)
            {
                pageIndex = 1;
                pageSize = 5;
            }

            if (string.IsNullOrWhiteSpace(id))
            {
                if (!string.IsNullOrEmpty(ProductdName) && string.IsNullOrEmpty(CategoryName))
                {
                    return await GetProductsName(ProductdName, CategoryName);
                }
                if (string.IsNullOrEmpty(ProductdName) && !string.IsNullOrEmpty(CategoryName))
                {
                    return await GetProductsName(ProductdName, CategoryName);
                }
            }
            return await GetProducts(id, pageIndex, pageSize);
        }

        public async Task<BasePaginatedList<ProductResponseDTO>> GetProducts(string? id, int pageIndex, int pageSize)
        {
            IQueryable<Products> query = _unitOfWork.GetRepository<Products>().Entities;
            if (pageIndex == 0 || pageSize == 0)
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
                preOrder.Status = PreOrderStatus.Available;
                await _unitOfWork.GetRepository<PreOrders>().UpdateAsync(preOrder);
            }

            await _unitOfWork.SaveAsync();
        }

        public async Task UpdateProducts(string id, ProductsModel productsModel)
        {
            Products product = await _unitOfWork.GetRepository<Products>().GetByIdAsync(id)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, $"Doesn't exist{id}");

            var oldQuantityInStock = product.QuantityInStock;
            string oldImageUrl = product.ImageUrl;

            _mapper.Map(productsModel, product);
            product.LastUpdatedTime = CoreHelper.SystemTimeNow;

            if (productsModel.Image != null)
            {
                product.ImageUrl = await _cloudinaryService.UploadImageAsync(productsModel.Image);

                if (!string.IsNullOrEmpty(oldImageUrl))
                {
                    var publicId = oldImageUrl.Split('/').Last().Split('.')[0];
                    await _cloudinaryService.DeleteImageAsync(publicId);
                }
            }
            else
            {
                product.ImageUrl = oldImageUrl;
            }

            await _unitOfWork.GetRepository<Products>().UpdateAsync(product);
            await _unitOfWork.SaveAsync();

            if (product.QuantityInStock > 0 && oldQuantityInStock <= 0)
            {
                await UpdatePreOrdersDeletedTime(product.Id);
            }
        }

    }
}
