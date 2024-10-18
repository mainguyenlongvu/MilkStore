using Microsoft.AspNetCore.Http;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Core;
using MilkStore.ModelViews.ProductsModelViews;
using MilkStore.ModelViews.ResponseDTO;

namespace MilkStore.Contract.Services.Interface
{
    public interface IProductsService
    {
        Task<BasePaginatedList<ProductResponseDTO>> GetProductByNameId(string? id, int pageIndex, int pageSize, string? ProductdName, string? CategoryName);
        Task<BasePaginatedList<ProductResponseDTO>> GetProducts(string id, int pageIndex, int pageSize);
        Task CreateProducts(ProductsModel createProductModel);
        Task UpdateProducts(string id, ProductsModel productsModel);
        Task DeleteProducts(string id);
        Task<BasePaginatedList<ProductResponseDTO>> GetProductsName(string? ProductdName, string? CategoryName);
    }
}
